# scripts/run_fleet_gate.ps1 — RAWRXD_LOCAL_AGENT_FLEET_001 runner
#
# Resolves each proposed fleet model's weight blob from its Ollama manifest,
# then runs the Deep2-only fleet gate binary against it. Per-model receipts
# land in the gate dir; a fleet-level summary is printed at the end.
#
# Usage:
#   pwsh -File scripts/run_fleet_gate.ps1 [-BuildDir build_p2] [-Tokens 32] [-Only name1,name2]

param(
    [string]$BuildDir = "build_p2",
    [int]$Tokens = 32,
    [string]$Only = "",
    [string]$ManifestRoot = "F:\OllamaModels\manifests\registry.ollama.ai",
    [string]$BlobRoot = "F:\OllamaModels\blobs",
    [string]$ReceiptDir = "F:\~dev\rawrxd\evidence\RAWRXD_LOCAL_AGENT_FLEET_001"
)

$ErrorActionPreference = 'Stop'

# Fleet ladder: name -> manifest family/tag. Order = smallest -> largest.
$Fleet = [ordered]@{
    'nemotron-3-nano:4b'            = @('library\nemotron-3-nano', '4b')
    'qwen3:8b'                      = @('library\qwen3', '8b')
    'deepseek-coder-v2:16b'         = @('library\deepseek-coder-v2', '16b')
    'nemotron-3.5-lightning:30b'    = @('library\nemotron-3.5-lightning', '30b')
    'deepseek-r1:32b'               = @('library\deepseek-r1', '32b')
    'qwen3-next:80b'                = @('library\qwen3-next', '80b')
    'gpt-oss:120b'                  = @('library\gpt-oss', '120b')
    'bluehawana/deepseek-v4-flash:iq2_m' = @('bluehawana\deepseek-v4-flash', 'iq2_m')
}

$exe = Join-Path $BuildDir 'bin\Release\fleet_gate.exe'
if (-not (Test-Path $exe)) { $exe = Join-Path $BuildDir 'bin\fleet_gate.exe' }
if (-not (Test-Path $exe)) { throw "fleet_gate.exe not found under $BuildDir" }

New-Item -ItemType Directory -Force -Path $ReceiptDir | Out-Null

$results = @()
foreach ($kv in $Fleet.GetEnumerator()) {
    $name = $kv.Key
    if ($Only -and ($name -notmatch [regex]::Escape($Only))) { continue }

    $family, $tag = $kv.Value
    $mf = Join-Path (Join-Path $ManifestRoot $family) $tag
    if (-not (Test-Path $mf)) {
        Write-Host "SKIP (no manifest): $name"
        $results += [pscustomobject]@{ Model = $name; Verdict = 'NO_MANIFEST'; TPS = '' ; Generated = '' }
        continue
    }

    $j = Get-Content $mf -Raw | ConvertFrom-Json
    $big = $j.layers | Sort-Object { [int64]($_.size -replace '\D', '') } -Descending | Select-Object -First 1
    if (-not $big) {
        Write-Host "SKIP (empty manifest): $name"
        $results += [pscustomobject]@{ Model = $name; Verdict = 'EMPTY_MANIFEST'; TPS = ''; Generated = '' }
        continue
    }
    $digest = $big.digest -replace ':', '-'
    $blob = Join-Path $BlobRoot $digest

    if (-not (Test-Path $blob)) {
        Write-Host "SKIP (blob missing): $name"
        $results += [pscustomobject]@{ Model = $name; Verdict = 'BLOB_MISSING'; TPS = ''; Generated = '' }
        continue
    }

    $receipt = Join-Path $ReceiptDir (($name -replace '[\\/:]', '_') + '.txt')
    Write-Host "RUN: $name ($([math]::Round($big.size/1GB,2)) GB) -> $receipt"

    & $exe $blob $Tokens $receipt 2>&1 | Tee-Object -Variable out
    $verdictLine = $out | Select-String -Pattern 'RAWRXD_LOCAL_AGENT_FLEET_001=(PASS|HOLD)' | Select-Object -Last 1
    $verdict = if ($verdictLine) { $verdictLine.Matches[0].Groups[1].Value } else { 'NO_VERDICT' }
    $tpsLine = $out | Select-String -Pattern 'DECODE_TPS_QPC=([0-9.]+)' | Select-Object -Last 1
    $tps = if ($tpsLine) { $tpsLine.Matches[0].Groups[1].Value } else { '' }
    $genLine = $out | Select-String -Pattern 'GENERATED=(\d+)' | Select-Object -Last 1
    $gen = if ($genLine) { $genLine.Matches[0].Groups[1].Value } else { '' }

    $results += [pscustomobject]@{ Model = $name; Verdict = $verdict; TPS = $tps; Generated = $gen }
}

Write-Host ''
Write-Host '=== RAWRXD_LOCAL_AGENT_FLEET_001 SUMMARY ==='
$results | Format-Table -AutoSize

$passCount = ($results | Where-Object Verdict -eq 'PASS').Count
$runCount  = ($results | Where-Object { $_.Verdict -notin 'NO_MANIFEST','EMPTY_MANIFEST','BLOB_MISSING','NO_VERDICT' }).Count
Write-Host "PASS=$passCount RUN=$runCount TOTAL=$($results.Count)"

if ($passCount -eq $runCount -and $runCount -gt 0) {
    Write-Host 'FLEET_VERDICT=PASS'
    exit 0
}
Write-Host 'FLEET_VERDICT=HOLD'
exit 1