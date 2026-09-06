#Requires -Version 5.1
<#
.SYNOPSIS
  Smoke MARS E2E against G:\OllamaModels blobs (manifest-resolved GGUF).

.PARAMETER MaxModels
  Cap how many distinct blobs to exercise (default 4).

.PARAMETER MaxTokens
  Tokens to generate per model (default 4).

.PARAMETER Exe
  Path to deep2_mars_e2e.exe
#>
param(
  [int]$MaxModels = 4,
  [int]$MaxTokens = 4,
  [string]$BlobsRoot = "G:\OllamaModels",
  [string]$Exe = "F:\~dev\rawrxd\build-ninja\bin\deep2_mars_e2e.exe",
  [string]$OutDir = "F:\~dev\rawrxd\build-ninja\bin\mars_smoke"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Resolve-BlobPath([string]$digest) {
  if (-not $digest) { return $null }
  $hash = $digest -replace '^sha256:', ''
  foreach ($p in @(
      (Join-Path $BlobsRoot "blobs\sha256-$hash"),
      (Join-Path $BlobsRoot "blobs\$hash")
    )) {
    if (Test-Path $p) { return (Get-Item $p).FullName }
  }
  return $null
}

if (-not (Test-Path $Exe)) {
  Write-Error "Missing harness: $Exe — build deep2_mars_e2e first"
}

# Prefer smaller present GGUF blobs for smoke (0.5–8 GB)
$candidates = @()
$seen = @{}
Get-ChildItem (Join-Path $BlobsRoot "manifests") -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
  try {
    $j = Get-Content $_.FullName -Raw | ConvertFrom-Json
    $layer = $j.layers | Where-Object { $_.mediaType -eq 'application/vnd.ollama.image.model' } | Select-Object -First 1
    if (-not $layer) { return }
    $blob = Resolve-BlobPath $layer.digest
    if (-not $blob) { return }
    $len = (Get-Item $blob).Length
    if ($len -lt 500MB -or $len -gt 8GB) { return }
    if ($seen.ContainsKey($blob)) { return }
    $seen[$blob] = $true
    $candidates += [PSCustomObject]@{
      Manifest = $_.FullName.Replace((Join-Path $BlobsRoot "manifests\") , "")
      Blob     = $blob
      GB       = [math]::Round($len / 1GB, 2)
    }
  } catch {}
}

$candidates = $candidates | Sort-Object GB | Select-Object -First $MaxModels
if (-not $candidates -or $candidates.Count -eq 0) {
  # Fallback: direct phi3 mini blob
  $fallback = Join-Path $BlobsRoot "blobs\sha256-633fc5be925f9a484b61d6f9b9a78021eeb462100bd557309f01ba84cac26adf"
  if (Test-Path $fallback) {
    $candidates = @([PSCustomObject]@{ Manifest = "phi3/mini"; Blob = $fallback; GB = 2.03 })
  } else {
    Write-Error "No smoke-sized blobs found under $BlobsRoot"
  }
}

Write-Host "=== MARS blob smoke ($($candidates.Count) models) ==="
$results = @()
foreach ($c in $candidates) {
  $tag = ($c.Manifest -replace '[\\/:]', '_')
  $stdout = Join-Path $OutDir "$tag.out.txt"
  $stderr = Join-Path $OutDir "$tag.err.txt"
  Write-Host ("-- {0} ({1} GB)" -f $c.Manifest, $c.GB)
  $p = Start-Process -FilePath $Exe -ArgumentList @($c.Blob, "$MaxTokens") `
    -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
    -Wait -PassThru -NoNewWindow
  $verdictLine = Select-String -Path $stdout -Pattern 'RAWRXD_DEEP2_MARS=' -SimpleMatch -ErrorAction SilentlyContinue |
    Select-Object -Last 1 -ExpandProperty Line
  $pass = ($p.ExitCode -eq 0) -and ($verdictLine -match 'PASS')
  $results += [PSCustomObject]@{
    Manifest = $c.Manifest
    Blob     = $c.Blob
    GB       = $c.GB
    ExitCode = $p.ExitCode
    Verdict  = $verdictLine
    Pass     = $pass
  }
  Write-Host ("   exit={0} {1}" -f $p.ExitCode, $verdictLine)
}

$summary = Join-Path $OutDir "MARS_BLOB_SMOKE_SUMMARY.txt"
$passN = ($results | Where-Object Pass).Count
$lines = @("RAWRXD_MARS_BLOB_SMOKE=$([string](if ($passN -eq $results.Count) { 'PASS' } else { 'FAIL' }))")
$lines += "models=$passN/$($results.Count)"
foreach ($r in $results) {
  $lines += ("{0} {1} exit={2} {3}" -f ($(if ($r.Pass) { 'PASS' } else { 'FAIL' })), $r.Manifest, $r.ExitCode, $r.Verdict)
}
$lines | Set-Content -Path $summary -Encoding UTF8
Write-Host "=== summary: $summary ($passN/$($results.Count)) ==="
if ($passN -ne $results.Count) { exit 1 }
exit 0
