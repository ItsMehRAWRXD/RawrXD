param(
  [string]$Ev = 'G:\~dev\rawrxd\evidence\REAP_STRATA_UNSLOTH_OLLAMA_BENCH_001',
  [string]$Exe = 'G:\~dev\rawrxd\build_ninja\bin\rawr.exe'
)
$ErrorActionPreference = 'Continue'
$d2 = Join-Path $Ev 'deep2'
New-Item -ItemType Directory -Force -Path $d2 | Out-Null
$csv = Join-Path $Ev 'DEEP2_MATRIX.csv'
"Name,Exe,Exit,GeneratedTokens,TpsLine,Disposition,Log" | Set-Content $csv -Encoding ascii
if (-not (Test-Path -LiteralPath $Exe)) {
  "EXE_MISSING,$Exe,-1,0,,NOT_RUN," | Add-Content $csv
  return
}
$ggufs = @(
  @{ Name='MiniMax-M2_7-Q4_K_M-REAP24'; Path='F:\OllamaModels\_REAP16\MiniMax-M2_7-Q4_K_M-REAP24\MiniMax-M2.7-Q4_K_M-00001-of-00003.gguf' },
  @{ Name='Qwen3_6-35B-A3B-GGUF-REAP199'; Path='F:\OllamaModels\_REAP16\Qwen3_6-35B-A3B-GGUF-REAP199\Qwen3.6-35B-A3B-Q4_K_M.gguf' },
  @{ Name='GLM-4_7-Flash-GGUF-REAP59'; Path='F:\OllamaModels\_REAP16\GLM-4_7-Flash-GGUF-REAP59\GLM-4.7-Flash-Q4_K_M.gguf' },
  @{ Name='nemotron-3_5-lightning-30b-REAP81'; Path='F:\OllamaModels\_REAP16\nemotron-3_5-lightning-30b-REAP81\sha256-5c19f6282f4fc51cb114cb6c876d70ca2fc3b9cf0fbd0a018d9908f4fe1f63b3' },
  @{ Name='ornith-1_5-35b-REAP194'; Path='F:\OllamaModels\_REAP16\ornith-1_5-35b-REAP194\sha256-aaeb640f98a892980ef54876024293cc8d6987a86523aa1b947ffa9274ef800a' },
  @{ Name='laguna-s-2_1-Q4_K_M-REAP35'; Path='F:\OllamaModels\_REAP16\laguna-s-2_1-Q4_K_M-REAP35\sha256-948255a146c07678678183af4cb1234a124e945e48c85c2006598ef4696552c8' }
)
foreach ($g in $ggufs) {
  $safe = ($g.Name -replace '[\\/:\*\?]', '_')
  $log = Join-Path $d2 "$safe.log"
  $err = Join-Path $d2 "$safe.err.log"
  Write-Host "DEEP2_BENCH $($g.Name)"
  if (-not (Test-Path -LiteralPath $g.Path)) {
    "$($g.Name),$Exe,-1,0,,NOT_RUN,missing_gguf" | Add-Content $csv
    continue
  }
  $p = Start-Process -FilePath $Exe -ArgumentList @('run', $g.Path, '-p', 'Say hi in one short sentence.', '--max-tokens', '32') `
    -NoNewWindow -PassThru -RedirectStandardOutput $log -RedirectStandardError $err
  $ok = $p.WaitForExit(480000)
  if (-not $ok) {
    try { $p.Kill() } catch {}
    "$($g.Name),$Exe,-1,0,,NOT_RUN,$log" | Add-Content $csv
    continue
  }
  $exit = $p.ExitCode
  $all = ''
  if (Test-Path $log) { $all += Get-Content -Raw $log }
  if (Test-Path $err) { $all += Get-Content -Raw $err }
  $gen = 0
  if ($all -match 'GENERATED_TOKENS[=:\s]+(\d+)') { $gen = [int]$Matches[1] }
  elseif ($all -match 'generated[_\s]?tokens[=:\s]+(\d+)') { $gen = [int]$Matches[1] }
  $tps = ''
  if ($all -match '(?i)(tok(?:ens)?[/_\s]?s(?:ec)?|TPS|Decode\s*≈?\s*[\d.]+)') {
    $m = [regex]::Match($all, '(?i)(?:tok(?:ens)?[/\s]?s(?:ec)?|TPS)[=:\s]+([\d.]+)')
    if ($m.Success) { $tps = $m.Groups[1].Value }
  }
  $disp = if ($exit -eq 0 -and $gen -gt 0) { 'PASS' } elseif ($exit -ne 0) { 'FAIL' } else { 'FAIL' }
  if ($all -match '(?i)HOST_DECODE|GPU.*(fail|error)|failed to load|not supported') {
    if ($gen -le 0) { $disp = 'FAIL' }
  }
  "$($g.Name),$Exe,$exit,$gen,$tps,$disp,$log" | Add-Content $csv
  Write-Host "DEEP2 $($g.Name) EXIT=$exit GEN=$gen DISP=$disp"
}
"DEEP2_DONE $(Get-Date -Format o)" | Set-Content (Join-Path $Ev 'DEEP2_DONE.txt')
Get-Content $csv
