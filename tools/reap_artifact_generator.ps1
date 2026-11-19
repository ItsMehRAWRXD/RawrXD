[CmdletBinding()]
param(
    [string]$SourceRoot = 'F:\OllamaModels',
    [string]$DestinationRoot = 'D:\OllamaModels2\reap-artifacts',
    [string]$RawrReap = 'D:\OllamaModels2\certification-build-cpu2\bin-msvc\Release\rawr-reap.exe',
    [UInt64]$TargetBytes = 17179869184,
    [UInt32]$ActiveExperts = 4,
    [switch]$ExperimentalOffline,
    [switch]$InventoryOnly
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $DestinationRoot | Out-Null
$receiptDir = Join-Path $DestinationRoot 'receipts'
New-Item -ItemType Directory -Force -Path $receiptDir | Out-Null

function Invoke-JsonTool([string[]]$Arguments) {
    $raw = & $RawrReap @Arguments 2>$null
    $exit = $LASTEXITCODE
    $json = $null
    try { $json = ($raw -join "`n") | ConvertFrom-Json } catch { }
    return [pscustomobject]@{ ExitCode = $exit; Json = $json; Raw = ($raw -join "`n") }
}

$firstShards = Get-ChildItem -LiteralPath $SourceRoot -Recurse -File -Filter '*.gguf' |
    Where-Object { $_.Name -match '-00001-of-\d+\.gguf$' } |
    Sort-Object FullName

$inventory = @()
foreach ($first in $firstShards) {
    $safe = ($first.BaseName -replace '[^A-Za-z0-9._-]', '_')
    $receipt = Join-Path $receiptDir ($safe + '.json')
    if ((Test-Path $receipt) -and -not $InventoryOnly) {
        $inventory += (Get-Content $receipt -Raw | ConvertFrom-Json)
        continue
    }
    $probe = Invoke-JsonTool @('inspect', $first.FullName)
    $item = [ordered]@{
        schema = 'rawrxd.reap.artifact_generator.v1'
        source = $first.FullName
        source_bytes = [UInt64]$first.Length
        discovered = $true
        inspect_exit = $probe.ExitCode
        inspect = $probe.Json
        eligible = $false
        status = 'BLOCKED'
        reason = 'inspect_failed'
        output = $null
        output_bytes = 0
    }
    if ($probe.ExitCode -eq 0 -and $probe.Json) {
        $item.eligible = ([UInt64]$probe.Json.bytes -gt $TargetBytes -and [UInt64]$probe.Json.expert_tensors -gt 0)
        if (-not $item.eligible) { $item.status = 'NO_CHANGE_REQUIRED'; $item.reason = 'already_within_target_or_not_moe' }
        else { $item.reason = 'eligible_moe_requires_selection_and_calibration' }
    }
    $item | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receipt -Encoding UTF8
    $inventory += [pscustomobject]$item
}

if ($InventoryOnly) {
    $inventory | ConvertTo-Json -Depth 8
    exit 0
}

foreach ($item in $inventory | Where-Object { $_.eligible -eq $true }) {
    $source = [string]$item.source
    $name = [IO.Path]::GetFileNameWithoutExtension($source) -replace '-00001-of-\d+$',''
    $outDir = Join-Path $DestinationRoot $name
    $receipt = Join-Path $receiptDir (($name -replace '[^A-Za-z0-9._-]', '_') + '.json')
    $args = @('reap', $source, '--target-size', $TargetBytes, '--active-experts', $ActiveExperts,
              '--expert-budget', $TargetBytes, '--quality-floor', '0.99',
              '--selection-output', (Join-Path $receiptDir ($name + '.selection.json')),
              '--output-model', $outDir, '--output', $receipt)
    if ($ExperimentalOffline) { $args += '--experimental-offline' }
    $run = Invoke-JsonTool $args
    $run.Raw | Set-Content -LiteralPath (Join-Path $receiptDir ($name + '.stdout.json')) -Encoding UTF8
}

$inventory | ConvertTo-Json -Depth 8
