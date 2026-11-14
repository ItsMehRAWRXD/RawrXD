param(
  [string]$Ev = 'G:\~dev\rawrxd\evidence\REAP_STRATA_UNSLOTH_OLLAMA_BENCH_001',
  [switch]$CreateOnly,
  [switch]$BenchOnly
)
$ErrorActionPreference = 'Continue'
$runs = Join-Path $Ev 'runs'
$mfDir = Join-Path $Ev 'modelfiles'
$olDir = Join-Path $Ev 'ollama'
New-Item -ItemType Directory -Force -Path $runs, $mfDir, $olDir | Out-Null
$prompt = 'Say hi in one short sentence.'
$asof = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK'
$strata = @(
  @{ Short='minimax-m2_7'; Tag='reap16-minimax-m2_7'; Peer=''; PeerTag=''; GguF='F:\OllamaModels\_REAP16\MiniMax-M2_7-Q4_K_M-REAP24\MiniMax-M2.7-Q4_K_M-00001-of-00003.gguf'; Name='MiniMax-M2_7-Q4_K_M-REAP24'; GiB=14.123; MultiShard=1 },
  @{ Short='qwen3_6-35b'; Tag='reap16-qwen3_6-35b'; Peer='FULL_OLLAMA'; PeerTag='qwen36-reference-local:latest'; GguF='F:\OllamaModels\_REAP16\Qwen3_6-35B-A3B-GGUF-REAP199\Qwen3.6-35B-A3B-Q4_K_M.gguf'; Name='Qwen3_6-35B-A3B-GGUF-REAP199'; GiB=15.651; MultiShard=0 },
  @{ Short='glm-4_7-flash'; Tag='reap16-glm-4_7-flash'; Peer=''; PeerTag=''; GguF='F:\OllamaModels\_REAP16\GLM-4_7-Flash-GGUF-REAP59\GLM-4.7-Flash-Q4_K_M.gguf'; Name='GLM-4_7-Flash-GGUF-REAP59'; GiB=15.665; MultiShard=0 },
  @{ Short='nemotron-3_5'; Tag='reap16-nemotron-3_5'; Peer='FULL_OLLAMA'; PeerTag='nemotron-3.5-lightning:30b'; GguF='F:\OllamaModels\_REAP16\nemotron-3_5-lightning-30b-REAP81\sha256-5c19f6282f4fc51cb114cb6c876d70ca2fc3b9cf0fbd0a018d9908f4fe1f63b3'; Name='nemotron-3_5-lightning-30b-REAP81'; GiB=15.566; MultiShard=0 },
  @{ Short='ornith-1_5'; Tag='reap16-ornith-1_5'; Peer='FULL_OLLAMA'; PeerTag='ornith-1.5:35b'; GguF='F:\OllamaModels\_REAP16\ornith-1_5-35b-REAP194\sha256-aaeb640f98a892980ef54876024293cc8d6987a86523aa1b947ffa9274ef800a'; Name='ornith-1_5-35b-REAP194'; GiB=15.686; MultiShard=0 },
  @{ Short='laguna-s-2_1'; Tag='reap16-laguna-s-2_1'; Peer='FULL_OLLAMA'; PeerTag='laguna-s-2.1:Q4_K_M'; GguF='F:\OllamaModels\_REAP16\laguna-s-2_1-Q4_K_M-REAP35\sha256-948255a146c07678678183af4cb1234a124e945e48c85c2006598ef4696552c8'; Name='laguna-s-2_1-Q4_K_M-REAP35'; GiB=15.629; MultiShard=0 }
)

function Get-UnslothSrc([string]$gguf) {
  if (-not (Test-Path -LiteralPath $gguf)) { return 'UNKNOWN' }
  if ($gguf -match '(?i)unsloth') { return '1' }
  $fs = [IO.File]::OpenRead($gguf)
  try {
    $buf = New-Object byte[] (2MB)
    $got = $fs.Read($buf, 0, $buf.Length)
    $s = [Text.Encoding]::ASCII.GetString($buf, 0, $got)
    if ($s -match '(?i)unsloth') { return '1' }
  } finally { $fs.Close() }
  return '0'
}

function Test-OllamaTag([string]$tag) {
  $raw = curl.exe -s --max-time 10 http://127.0.0.1:11434/api/tags 2>$null
  if (-not $raw) { return $false }
  $models = ($raw | ConvertFrom-Json).models
  foreach ($m in $models) {
    if ($m.name -eq $tag -or $m.name -eq "$tag`:latest" -or $m.name.StartsWith("$tag`:")) { return $true }
  }
  return $false
}

function Ensure-Model([hashtable]$s) {
  $log = Join-Path $runs ("create_{0}.log" -f $s.Short)
  $mf = Join-Path $mfDir ("Modelfile.{0}" -f $s.Short)
  "FROM $($s.GguF)" | Set-Content -LiteralPath $mf -Encoding ascii
  if (Test-OllamaTag $s.Tag) {
    Set-Content -LiteralPath $log -Value "SKIP_CREATE tag=$($s.Tag) already present" -Encoding ascii
    Write-Host "SKIP_CREATE $($s.Tag)"
    return 'OK'
  }
  if (-not (Test-Path -LiteralPath $s.GguF)) {
    Set-Content -LiteralPath $log -Value "FAIL missing GGUF $($s.GguF)" -Encoding ascii
    Write-Host "FAIL missing $($s.GguF)"
    return 'FAIL'
  }
  Write-Host "CREATE $($s.Tag) FROM $($s.GguF)"
  & ollama create $s.Tag -f $mf *> $log
  if (Test-OllamaTag $s.Tag) {
    Write-Host "OK create $($s.Tag)"
    return 'OK'
  }
  $xc = $LASTEXITCODE
  Add-Content $log "FAIL create exit=$xc"
  Write-Host "FAIL create $($s.Tag) exit=$xc"
  return 'FAIL'
}

function Bench-Tag([string]$tag, [string]$peer, [string]$stratum) {
  $safe = ($tag -replace '[\\/:\*\?]', '_')
  $bodyPath = Join-Path $olDir "$safe.body.json"
  $tmp = Join-Path $olDir "$safe.json"
  $cerr = Join-Path $olDir "$safe.curl.err"
  $bodyObj = [ordered]@{
    model = $tag; prompt = $prompt; stream = $false
    options = [ordered]@{ num_predict = 32; temperature = 0 }
  }
  $utf8 = New-Object System.Text.UTF8Encoding $false
  [IO.File]::WriteAllText($bodyPath, ($bodyObj | ConvertTo-Json -Compress -Depth 5), $utf8)
  Write-Host "OLLAMA_BENCH $tag peer=$peer"
  $sw = [Diagnostics.Stopwatch]::StartNew()
  & curl.exe -sS --max-time 1800 -H 'Content-Type: application/json' --data-binary "@$bodyPath" "http://127.0.0.1:11434/api/generate" -o $tmp 2>$cerr
  $sw.Stop()
  $row = [ordered]@{
    Name=$tag; Peer=$peer; Stratum=$stratum; EvalCount=0; EvalNs=0
    PromptEvalCount=0; PromptEvalNs=0; TokPerSec=0; LoadDurNs=0
    TotalMs=$sw.ElapsedMilliseconds; HttpOk='False'; Disposition='FAIL'; Log=$tmp
  }
  try {
    if ((Test-Path $tmp) -and ((Get-Item $tmp).Length -gt 10)) {
      $j = Get-Content -LiteralPath $tmp -Raw | ConvertFrom-Json
      $eval = [int64]$j.eval_count; $ens = [int64]$j.eval_duration
      $tps = if ($ens -gt 0) { [math]::Round(($eval * 1e9) / $ens, 3) } else { 0 }
      $ok = [bool]$j.done
      $disp = if ($ok -and $eval -gt 0) { 'PASS' } else { 'FAIL' }
      $row.EvalCount = $eval; $row.EvalNs = $ens
      $row.PromptEvalCount = $j.prompt_eval_count; $row.PromptEvalNs = $j.prompt_eval_duration
      $row.TokPerSec = $tps; $row.LoadDurNs = $j.load_duration
      $row.HttpOk = $ok; $row.Disposition = $disp
    } else {
      $row.Disposition = 'FAIL'
      if (Test-Path $cerr) { Get-Content -Raw $cerr | Out-File (Join-Path $runs "$safe.create_or_bench.err.txt") }
    }
  } catch {
    $row.Disposition = 'FAIL'
    "PARSE_FAIL $_" | Out-File (Join-Path $runs "$safe.parse.err.txt")
  }
  return $row
}

$createCsv = Join-Path $Ev 'CREATE_MATRIX.csv'
$ollamaCsv = Join-Path $Ev 'OLLAMA_MATRIX.csv'
$strataCsv = Join-Path $Ev 'STRATA_MATRIX.csv'
"Short,Tag,GguF,CreateDisp,UnslothSrc,MultiShard" | Set-Content $createCsv -Encoding ascii
"Name,Peer,Stratum,EvalCount,EvalNs,PromptEvalCount,PromptEvalNs,TokPerSec,LoadDurNs,TotalMs,HttpOk,Disposition,Log" | Set-Content $ollamaCsv -Encoding ascii
"Name,OllamaTag,OllamaTps,OllamaDisp,Deep2Disp,UnslothSrc,Peer,PeerTps,Disposition,GiB" | Set-Content $strataCsv -Encoding ascii

curl.exe -s --max-time 5 http://127.0.0.1:11434/api/tags -o NUL

$createMap = @{}
foreach ($s in $strata) {
  $us = Get-UnslothSrc $s.GguF
  $cd = 'NOT_RUN'
  if ($BenchOnly) {
    $cd = if (Test-OllamaTag $s.Tag) { 'OK' } else { 'FAIL' }
  } else {
    $cd = Ensure-Model $s
  }
  $createMap[$s.Short] = @{ Disp=$cd; Unsloth=$us }
  "$($s.Short),$($s.Tag),$($s.GguF),$cd,$us,$($s.MultiShard)" | Add-Content $createCsv
}

if ($CreateOnly) { Get-Content $createCsv; return }

$ollamaRows = @()
foreach ($s in $strata) {
  $cd = $createMap[$s.Short].Disp
  $us = $createMap[$s.Short].Unsloth
  # PowerShell may coalesce pipeline noise; treat tag-present as OK
  if ($cd -ne 'OK' -and -not (Test-OllamaTag $s.Tag)) {
    $line = "$($s.Tag),REAP16,$($s.Name),0,0,0,0,0,0,0,False,NOT_RUN,"
    Add-Content $ollamaCsv $line
    "$($s.Name),$($s.Tag),0,NOT_RUN,NOT_RUN,$us,,0,NOT_RUN,$($s.GiB)" | Add-Content $strataCsv
    continue
  }
  $r = Bench-Tag $s.Tag 'REAP16' $s.Name
  $ollamaRows += $r
  "$($r.Name),$($r.Peer),$($r.Stratum),$($r.EvalCount),$($r.EvalNs),$($r.PromptEvalCount),$($r.PromptEvalNs),$($r.TokPerSec),$($r.LoadDurNs),$($r.TotalMs),$($r.HttpOk),$($r.Disposition),$($r.Log)" | Add-Content $ollamaCsv
  $peerTps = 0; $peerDisp = ''
  if ($s.PeerTag) {
    $pr = Bench-Tag $s.PeerTag 'FULL_OLLAMA' $s.Name
    $ollamaRows += $pr
    "$($pr.Name),$($pr.Peer),$($pr.Stratum),$($pr.EvalCount),$($pr.EvalNs),$($pr.PromptEvalCount),$($pr.PromptEvalNs),$($pr.TokPerSec),$($pr.LoadDurNs),$($pr.TotalMs),$($pr.HttpOk),$($pr.Disposition),$($pr.Log)" | Add-Content $ollamaCsv
    $peerTps = $pr.TokPerSec; $peerDisp = $pr.Disposition
  }
  $disp = $r.Disposition
  "$($s.Name),$($s.Tag),$($r.TokPerSec),$disp,NOT_RUN,$us,$($s.Peer),$peerTps,$disp,$($s.GiB)" | Add-Content $strataCsv
}

"OLLAMA_DONE $asof" | Set-Content (Join-Path $Ev 'OLLAMA_DONE.txt')
Get-Content $ollamaCsv
Get-Content $strataCsv
