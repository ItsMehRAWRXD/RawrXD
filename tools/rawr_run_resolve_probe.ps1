# Resolve-only probe: kill after MODEL/PATH (+ stream enter), not after 256 tokens.
# HARNESS_STOP_AFTER_RESOLVE != PRODUCT_FAILURE
param(
  [Parameter(Mandatory=$true)][string]$Alias,
  [string]$Prompt = 'hi',
  [string]$OutDir = 'G:\~dev\rawrxd\evidence\RAWR_RUN_WALK',
  [string]$Rawr = 'G:\~dev\rawrxd\build-fd\bin\rawr.exe'
)

$ErrorActionPreference = 'Continue'
$env:RAWRXD_HOST_DECODE = '1'
$env:RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM = '1'
$env:RAWRXD_DEEP2_ALLOW_BYTE_TOKENIZER = '1'
$env:RAWRXD_MODEL_ROOT = 'F:\OllamaModels'
$env:RAWRXD_KEEP_ENHANCE_SKIP = '1'
$env:RAWRXD_ENHANCE_SKIP = 'elastic,cyclone,ckv,mars,medusa,nvme,vulkan,warmup,nu,chamber,plasma,sov,prefetch,telemetry,slide'

New-Item -ItemType Directory -Force $OutDir | Out-Null
$safe = ($Alias -replace '[:/\\]', '_')
$out = Join-Path $OutDir "run_${safe}.stdout.txt"
$err = Join-Path $OutDir "run_${safe}.stderr.txt"
Remove-Item $out, $err -EA SilentlyContinue

$p = Start-Process -FilePath $Rawr -ArgumentList @('run', $Alias, $Prompt) `
  -RedirectStandardOutput $out -RedirectStandardError $err -PassThru -NoNewWindow

$resolved = $false
$generated = $false
for ($i = 0; $i -lt 300; $i++) {
  Start-Sleep -Milliseconds 100
  $txt = @((Get-Content $out -Raw -EA SilentlyContinue),
           (Get-Content $err -Raw -EA SilentlyContinue)) -join "`n"
  if ($txt -match '(?m)^(MODEL|MODEL_PATH|PATH|MODEL_ALIAS|MODEL_RESOLVED)=') {
    $resolved = $true
  }
  if ($txt -match 'GENERATED_TOKENS=[1-9]' -or $txt -match 'TOKEN_COMMITTED=1') {
    $generated = $true
    break
  }
  if ($resolved -and ($txt -match '(PROMPT_TOKENS=|CHAT_TEMPLATE_SOURCE=|STREAM_STATUS=|GENERATE_STREAM_ENTER=1|CHAT_TEMPLATE_)')) {
    break
  }
  if ($p.HasExited) { break }
}

if (-not $p.HasExited) {
  Stop-Process -Id $p.Id -Force -EA SilentlyContinue
  $probeExit = 'HARNESS_STOP_AFTER_RESOLVE'
} else {
  $p.Refresh()
  $probeExit = "$($p.ExitCode)"
}

Write-Host "RESOLVED=$([int]$resolved)"
Write-Host "TOKEN_WITNESS=$([int]$generated)"
Write-Host "PROBE_EXIT=$probeExit"
Select-String -Path $out, $err `
  -Pattern '^(MODEL|MODEL_PATH|PATH|MODEL_ALIAS|MODEL_RESOLVED)=|PROMPT_TOKENS=|GENERATED_TOKENS=|CHAT_TEMPLATE_|STREAM_STATUS=|GENERATE_STREAM_ENTER=|failed to resolve' `
  -EA SilentlyContinue | ForEach-Object { $_.Line.Trim() } | Select-Object -Unique
