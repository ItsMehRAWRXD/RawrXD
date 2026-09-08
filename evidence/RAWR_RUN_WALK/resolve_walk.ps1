# Resolve-only walk: alias → local GGUF authority.
# HARNESS_STOP_AFTER_RESOLVE is allowed; not a product/TPS failure.
param(
    [string]$Alias = "nemotron-3-nano:4b",
    [string]$Prompt = "hi",
    [string]$BinDir = "G:\~dev\rawrxd\build-fd\bin",
    [string]$OutDir = "G:\~dev\rawrxd\evidence\RAWR_RUN_WALK"
)

$ErrorActionPreference = "Continue"
Set-Location $BinDir

$env:RAWRXD_HOST_DECODE = "1"
$env:RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM = "1"
$env:RAWRXD_DEEP2_ALLOW_BYTE_TOKENIZER = "1"
$env:RAWRXD_MODEL_ROOT = "F:\OllamaModels"
$env:RAWRXD_KEEP_ENHANCE_SKIP = "1"
$env:RAWRXD_ENHANCE_SKIP = "elastic,cyclone,ckv,mars,medusa,nvme,vulkan,warmup,nu,chamber,plasma,sov,prefetch,telemetry,slide"
Remove-Item Env:DEEP2_K2_SHARD_DIR -EA SilentlyContinue

New-Item -ItemType Directory -Force $OutDir | Out-Null
$safe = ($Alias -replace '[:/\\]', '_')
$out = Join-Path $OutDir "run_${safe}.stdout.txt"
$err = Join-Path $OutDir "run_${safe}.stderr.txt"
Remove-Item $out, $err -EA SilentlyContinue

Write-Host "==== resolve $Alias ===="
$p = Start-Process -FilePath ".\rawr.exe" `
    -ArgumentList @("run", $Alias, $Prompt) `
    -RedirectStandardOutput $out -RedirectStandardError $err `
    -PassThru -NoNewWindow

$resolved = $false
$generated = $false
for ($i = 0; $i -lt 300; $i++) {
    Start-Sleep -Milliseconds 100
    $txt = @(
        Get-Content $out -Raw -EA SilentlyContinue
        Get-Content $err -Raw -EA SilentlyContinue
    ) -join "`n"
    if ($txt -match '(?m)^(MODEL|MODEL_PATH|PATH|MODEL_ALIAS|MODEL_RESOLVED)=') {
        $resolved = $true
    }
    if ($txt -match 'GENERATED_TOKENS=[1-9]' -or $txt -match 'TOKEN_COMMITTED=1') {
        $generated = $true
        break
    }
    if ($resolved -and
        $txt -match '(PROMPT_TOKENS=|CHAT_TEMPLATE_SOURCE=|STREAM_STATUS=|GENERATE_STREAM_ENTER=1)') {
        break
    }
    if ($p.HasExited) { break }
}

if (-not $p.HasExited) {
    Stop-Process -Id $p.Id -Force -EA SilentlyContinue
    $probeExit = "HARNESS_STOP_AFTER_RESOLVE"
} else {
    $p.Refresh()
    $probeExit = "$($p.ExitCode)"
}

Write-Host ""
Write-Host "==== authority ===="
Select-String -Path $out, $err `
    -Pattern '^(MODEL|MODEL_PATH|PATH|MODEL_ALIAS|MODEL_RESOLVED)=|PROMPT_TOKENS=|GENERATED_TOKENS=|CHAT_TEMPLATE_|BLOCKER_94|STREAM_STATUS=|GENERATE_STREAM_ENTER=|DECODE_ENTERED=|BLOCKED_AT=|BLOCKED_OWNER=|FAIL_REASON=|FAIL_OWNER=' `
    -EA SilentlyContinue |
    ForEach-Object { $_.Line.Trim() } |
    Select-Object -Unique

Write-Host "RESOLVED=$([int]$resolved)"
Write-Host "TOKEN_WITNESS=$([int]$generated)"
Write-Host "PROBE_EXIT=$probeExit"
Write-Host "HARNESS_STOP_NE_PRODUCT_FAILURE=1"
Write-Host "PRODUCT_PASS=not_evaluated"
Write-Host "TPS=not_evaluated"
