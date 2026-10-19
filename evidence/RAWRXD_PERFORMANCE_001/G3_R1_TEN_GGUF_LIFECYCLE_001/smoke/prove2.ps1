$ErrorActionPreference = 'Continue'
$ev = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_001'
$smoke = Join-Path $ev 'smoke'
$exe = 'G:\~dev\rawrxd\smoke_bin\RawrXD-Win32IDE_r1matrix.exe'
$port = 11435
$base = "http://127.0.0.1:$port"
$model = 'G:\~dev\rawrxd\_r1_models\01_tinyllama\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'
if (-not (Test-Path -LiteralPath $model)) {
  $model = 'G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'
}

Get-Process -Name 'RawrXD*' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

$env:RAWRXD_HOST_DECODE = '1'
$env:RAWRXD_FORCE_CPU_INFERENCE = '1'
$env:DEEP2_MINIMAL_ENHANCE = '1'
$env:DEEP2_DUALSTICK_ARM = '0'
$env:RAWRXD_NO_VULKAN = '1'
$env:DEEP2_MARS = '0'

$out = Join-Path $smoke 'prove2.out.txt'
$err = Join-Path $smoke 'prove2.err.txt'
Remove-Item $out, $err -ErrorAction SilentlyContinue
$p = Start-Process -FilePath $exe -ArgumentList @(
  '--headless','--local','--port',"$port",'--dir','G:\~dev\rawrxd'
) -WorkingDirectory (Split-Path $exe) -RedirectStandardOutput $out -RedirectStandardError $err -PassThru -WindowStyle Hidden

$ok = $false
for ($i = 0; $i -lt 60; $i++) {
  try {
    $h = Invoke-WebRequest -Uri "$base/api/engine/capabilities" -UseBasicParsing -TimeoutSec 2
    if ($h.StatusCode -eq 200) { $ok = $true; break }
  } catch {}
  Start-Sleep -Seconds 1
}
if (-not $ok) {
  Write-Host 'HEALTH_FAIL'
  Get-Content $err -Tail 40 -ErrorAction SilentlyContinue
  exit 1
}
Start-Sleep -Seconds 2
Write-Host "HEALTH_OK pid=$($p.Id)"

$sd = Join-Path $env:TEMP 'rawrxd_r1_bodies'
New-Item -ItemType Directory -Force -Path $sd | Out-Null

function Post-Json([string]$path, [string]$json, [string]$name) {
  $bf = Join-Path $sd $name
  $of = Join-Path $smoke $name
  [IO.File]::WriteAllText($bf, $json)
  $code = & curl.exe -sS -o $of -w '%{http_code}' -X POST "$base$path" `
    -H 'Content-Type: application/json' --data-binary "@$bf" --max-time 900 2>$null
  if (-not $code) { $code = '000' }
  $body = ''
  if (Test-Path -LiteralPath $of) { $body = [IO.File]::ReadAllText($of) }
  $alive = [bool](Get-Process -Name 'RawrXD*' -ErrorAction SilentlyContinue)
  Write-Host "$name CODE=$code LEN=$($body.Length) ALIVE=$alive"
  if ($body.Length -gt 0) {
    Write-Host ($body.Substring(0, [Math]::Min(240, $body.Length)))
  }
  return [int]$code
}

$loadJson = (@{ model = $model; modelPath = $model; path = $model } | ConvertTo-Json -Compress)
$genJson = (@{ prompt = 'Reply with exactly: OK'; stream = $false; options = @{ num_predict = 8 } } | ConvertTo-Json -Compress)

$c1 = Post-Json '/api/model/load' $loadJson 'p2_load.json'
$c2 = Post-Json '/api/generate' $genJson 'p2_gen1.json'
$c3 = Post-Json '/api/model/unload' '{}' 'p2_unload.json'
$c4 = Post-Json '/api/model/load' $loadJson 'p2_reload.json'
$c5 = Post-Json '/api/generate' $genJson 'p2_gen2.json'

$alive = [bool](Get-Process -Id $p.Id -ErrorAction SilentlyContinue)
Write-Host "FINAL ALIVE=$alive codes=$c1/$c2/$c3/$c4/$c5"
Write-Host '---ERR HITS---'
Select-String -Path $err -Pattern 'GENERATE_|NativeCIE|CIE_|hard-unload|Shutdown|FAILED|0xC000|Model armed|GENERATE_FAIL' -ErrorAction SilentlyContinue |
  Select-Object -Last 50 | ForEach-Object { $_.Line }

if ($alive) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }

if ($c1 -eq 200 -and $c2 -eq 200 -and $c3 -eq 200 -and $c4 -eq 200 -and $c5 -eq 200 -and $alive) {
  Write-Host 'PROVE_PASS=1'
  exit 0
}
Write-Host 'PROVE_PASS=0'
exit 2
