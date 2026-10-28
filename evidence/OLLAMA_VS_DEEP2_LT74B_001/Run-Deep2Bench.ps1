param([string]$Ev = 'G:\~dev\rawrxd\evidence\OLLAMA_VS_DEEP2_LT74B_001')
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path (Join-Path $Ev 'deep2') | Out-Null
$bench = 'F:\rawrxd\build_reap\bin\deep2_bench_tps.exe'
$rawr = 'G:\~dev\rawrxd\build-fd\bin\rawr.exe'
$env:RAWRXD_NO_OLLAMA = '1'
$env:RAWRXD_HOST_DECODE = '1'
$env:DEEP2_MINIMAL_ENHANCE = '1'

# Authority map: DEEP2_GGUF_MAP.json only (fail-closed if missing)
$mapPath = Join-Path $Ev 'DEEP2_GGUF_MAP.json'
$mapObj = Get-Content -Raw $mapPath | ConvertFrom-Json
$map = @{}
$mapObj.PSObject.Properties | ForEach-Object { $map[$_.Name] = [string]$_.Value }

$csv = Import-Csv (Join-Path $Ev 'ELIGIBLE_MODELS.csv')
$outCsv = Join-Path $Ev 'DEEP2_MATRIX.csv'
'Name,ParamsB,Gguf,TokPerSec,GeneratedTokens,Ms,Exit,Disposition,Tool' | Set-Content $outCsv

function Parse-Metrics([string]$txt) {
  $tps = 0.0; $tok = 0
  # Prefer decode throughput from deep2_bench_tps
  if ($txt -match 'DECODE_TPS=([\d.]+)') { $tps = [double]$Matches[1] }
  elseif ($txt -match 'STEADY_DECODE_TPS=([\d.]+)') { $tps = [double]$Matches[1] }
  elseif ($txt -match 'tok/s[=:\s]+([\d.]+)') { $tps = [double]$Matches[1] }
  elseif ($txt -match 'TPS[=:\s]+([\d.]+)') { $tps = [double]$Matches[1] }
  elseif ($txt -match 'decode_tps[=:\s]+([\d.]+)') { $tps = [double]$Matches[1] }
  elseif ($txt -match '([\d.]+)\s*tok/s') { $tps = [double]$Matches[1] }
  if ($txt -match 'GENERATED_TOKENS=(\d+)') { $tok = [int]$Matches[1] }
  elseif ($txt -match 'tokens_out=(\d+)') { $tok = [int]$Matches[1] }
  elseif ($txt -match 'tokens[=:\s]+(\d+)') { $tok = [int]$Matches[1] }
  return @{ Tps = $tps; Tok = $tok }
}

foreach ($r in $csv) {
  $name = $r.Name
  $gguf = $map[$name]
  if ([string]::IsNullOrWhiteSpace($gguf)) {
    $line = "$name,$($r.ParamsB),MISSING,0,0,0,0,NOT_RUN_NO_GGUF,none"
    Add-Content $outCsv $line; Write-Host $line; continue
  }
  if (-not (Test-Path -LiteralPath $gguf)) {
    $line = "$name,$($r.ParamsB),$gguf,0,0,0,0,MISSING_PATH,none"
    Add-Content $outCsv $line; Write-Host $line; continue
  }

  $safe = ($name -replace '[\\/:]', '_')
  $log = Join-Path $Ev ("deep2\$safe.log")
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $tool = 'deep2_bench_tps'
  $rc = -1

  if (Test-Path -LiteralPath $bench) {
    & $bench --model $gguf --tokens '1 32' --decode 32 --runs 1 2>&1 |
      Tee-Object -FilePath $log | Out-Null
    $rc = $LASTEXITCODE
  }

  $txt = if (Test-Path -LiteralPath $log) { Get-Content -Raw -LiteralPath $log } else { '' }
  $m = Parse-Metrics $txt

  # Fallback to rawr on tool failure / no metrics
  if (($rc -ne 0 -or ($m.Tps -le 0 -and $m.Tok -le 0)) -and (Test-Path -LiteralPath $rawr)) {
    $tool = 'rawr'
    & $rawr run $gguf --max-tokens 32 --prompt 'Say hi in one short sentence.' 2>&1 |
      Tee-Object -FilePath $log | Out-Null
    $rc = $LASTEXITCODE
    $txt = if (Test-Path -LiteralPath $log) { Get-Content -Raw -LiteralPath $log } else { '' }
    $m = Parse-Metrics $txt
  }

  $sw.Stop()
  $disp = if ($rc -eq 0 -and ($m.Tps -gt 0 -or $m.Tok -gt 0 -or $txt -match 'PRODUCT_PASS=1')) {
    'PASS'
  } elseif ($rc -eq 0) {
    'RUN_OK_NO_METRICS'
  } else {
    'FAIL'
  }
  $line = "$name,$($r.ParamsB),$gguf,$($m.Tps),$($m.Tok),$($sw.ElapsedMilliseconds),$rc,$disp,$tool"
  Add-Content $outCsv $line
  Write-Host $line
}

'DEEP2_DONE' | Set-Content (Join-Path $Ev 'DEEP2_DONE.txt')
Get-Content $outCsv
