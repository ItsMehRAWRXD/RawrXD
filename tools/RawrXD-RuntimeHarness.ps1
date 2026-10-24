param(
  [string]$Gateway = 'http://127.0.0.1:11435',
  [string]$Native = 'http://127.0.0.1:11436',
  [string]$Executable = '',
  [string]$Output = ''
)
$ErrorActionPreference = 'Stop'
$started = [DateTime]::UtcNow
function Probe([string]$Base,[string]$Path) {
  try {
    $r = Invoke-WebRequest -Uri ($Base.TrimEnd('/')+$Path) -Method Get -TimeoutSec 5 -UseBasicParsing
    [pscustomobject]@{ url=$Base.TrimEnd('/')+$Path; status=[int]$r.StatusCode; reachable=$true; body_bytes=([Text.Encoding]::UTF8.GetByteCount([string]$r.Content)); error='' }
  } catch {
    [pscustomobject]@{ url=$Base.TrimEnd('/')+$Path; status=0; reachable=$false; body_bytes=0; error=$_.Exception.Message }
  }
}
$probes = @(
  (Probe $Gateway '/health'), (Probe $Gateway '/v1/models'),
  (Probe $Native '/health'), (Probe $Native '/v1/models')
)
$exeInfo = $null
if ($Executable) {
  if (Test-Path -LiteralPath $Executable -PathType Leaf) {
    $item=Get-Item -LiteralPath $Executable
    $exeInfo=[pscustomobject]@{ path=$item.FullName; length=$item.Length; sha256=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash }
  } else { $exeInfo=[pscustomobject]@{ path=$Executable; missing=$true } }
}
$result=[ordered]@{
  schema='RAWRXD_RUNTIME_HARNESS_001'; started_utc=$started.ToString('o'); finished_utc=[DateTime]::UtcNow.ToString('o')
  probes=$probes; executable=$exeInfo
  inference_execution='NOT_RUN'; gpu_forward='NOT_RUN'; certification='NOT_CERTIFIED'
  note='Health/model probes are reachability evidence only; no certification is inferred.'
}
$json=$result | ConvertTo-Json -Depth 6
if ($Output) { $dir=Split-Path -Parent $Output; if($dir){New-Item -ItemType Directory -Force $dir | Out-Null}; Set-Content -LiteralPath $Output -Value $json -Encoding UTF8 }
$json
$required = @($probes | Where-Object { $_.url -match '/(health|v1/models)$' })
if (@($required | Where-Object { -not $_.reachable -or $_.status -lt 200 -or $_.status -ge 300 }).Count -gt 0) { exit 4 }
