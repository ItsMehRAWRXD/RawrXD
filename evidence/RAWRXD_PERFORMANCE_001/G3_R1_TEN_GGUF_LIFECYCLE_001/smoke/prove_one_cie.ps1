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
$tag = 'prove_cie'

Get-Process -Name 'RawrXD*' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

$env:RAWRXD_HOST_DECODE = '1'
$env:DEEP2_MINIMAL_ENHANCE = '1'
$env:DEEP2_DUALSTICK_ARM = '0'
$env:RAWRXD_NO_VULKAN = '1'
$env:RAWRXD_FORCE_CPU_INFERENCE = '1'
$env:OLLAMA_HOST = $base

$out = Join-Path $smoke "$tag.headless.out.txt"
$err = Join-Path $smoke "$tag.headless.err.txt"
Remove-Item $out, $err -ErrorAction SilentlyContinue
$p = Start-Process -FilePath $exe -ArgumentList @(
  '--headless','--local','--port',"$port",'--dir','G:\~dev\rawrxd'
) -WorkingDirectory (Split-Path $exe) -RedirectStandardOutput $out -RedirectStandardError $err -PassThru -WindowStyle Hidden

$ok = $false
$deadline = (Get-Date).AddSeconds(45)
while ((Get-Date) -lt $deadline) {
  try {
    $h = Invoke-WebRequest -Uri "$base/api/engine/capabilities" -UseBasicParsing -TimeoutSec 3
    if ($h.StatusCode -eq 200) { $ok = $true; break }
  } catch { Start-Sleep -Milliseconds 500 }
}
if (-not $ok) { Write-Host 'HEALTH_FAIL'; Get-Content $err -Tail 40; exit 1 }
Write-Host "HEALTH_OK pid=$($p.Id)"

$safeDir = Join-Path $env:TEMP 'rawrxd_r1_bodies'
New-Item -ItemType Directory -Force -Path $safeDir | Out-Null

function Post([string]$path, [string]$json, [string]$name) {
  $bf = Join-Path $safeDir $name
  $of = Join-Path $smoke $name
  [IO.File]::WriteAllText($bf, $json)
  $code = & curl.exe -sS -o $of -w '%{http_code}' -X POST "$base$path" -H 'Content-Type: application/json' --data-binary "@$bf" --max-time 900 2>$null
  $body = if (Test-Path $of) { [IO.File]::ReadAllText($of) } else { '' }
  Write-Host "$name CODE=$code LEN=$($body.Length)"
  Write-Host ($body.Substring(0, [Math]::Min(400, $body.Length)))
  return @{ Code=[int]$code; Body=$body }
}

$loadJson = (@{ model=$model; modelPath=$model; path=$model } | ConvertTo-Json -Compress)
$genJson = (@{ model='tinyllama'; prompt='Say hello in one short sentence.'; stream=$false; options=@{ num_predict=32 } } | ConvertTo-Json -Compress)

$r1 = Post '/api/model/load' $loadJson 'prove_load.json'
$r2 = Post '/api/generate' $genJson 'prove_gen1.json'
$r3 = Post '/api/model/unload' '{}' 'prove_unload.json'
$r4 = Post '/api/model/load' $loadJson 'prove_reload.json'
$r5 = Post '/api/generate' $genJson 'prove_gen2.json'

$alive = Get-Process -Id $p.Id -ErrorAction SilentlyContinue
Write-Host "ALIVE=$([bool]$alive) LOAD=$($r1.Code) GEN1=$($r2.Code) UNLOAD=$($r3.Code) RELOAD=$($r4.Code) GEN2=$($r5.Code)"
Write-Host '---ERR TAIL---'
Get-Content $err -Tail 60 -ErrorAction SilentlyContinue
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
