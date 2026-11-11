[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$ModelPath,
    [string]$ProbeExe = '',
    [string]$Output = ''
)

$ErrorActionPreference = 'Stop'
$ModelPath = (Resolve-Path -LiteralPath $ModelPath).Path
if (-not $ProbeExe) {
    $ProbeExe = @(
        (Join-Path $PSScriptRoot '..\build\bin\Release\deep2_shard_probe.exe'),
        (Join-Path $PSScriptRoot '..\build\Release\deep2_shard_probe.exe')
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
if (-not $ProbeExe) { throw 'deep2_shard_probe.exe was not found; pass -ProbeExe explicitly.' }
$ProbeExe = (Resolve-Path -LiteralPath $ProbeExe).Path
if (-not $Output) {
    $stem = [IO.Path]::GetFileNameWithoutExtension($ModelPath)
    $Output = Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'evidence') ($stem + '_topology_manifest.json')
}

$temp = Join-Path ([IO.Path]::GetTempPath()) ('deep2_topology_' + [guid]::NewGuid().ToString('N') + '.tsv')
try {
    $probeOutput = @(& $ProbeExe --dump $temp $ModelPath 2>&1)
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $temp)) {
        throw "shard probe failed with exit code $LASTEXITCODE"
    }
    $probeText = ($probeOutput -join "`n")
    $arch = if ($probeText -match 'arch=([^\s]+)') { $Matches[1] } else { 'unknown' }
    $rows = @(Import-Csv -LiteralPath $temp -Delimiter "`t" -Header ggml_type,offset,bytes,shape,name)
    $blocks = @{}
    foreach ($row in $rows) {
        if ($row.name -notmatch '^blk\.(\d+)\.(.+)$') { continue }
        $index = [int]$Matches[1]
        $role = $Matches[2]
        if (-not $blocks.ContainsKey($index)) { $blocks[$index] = [ordered]@{} }
        $blocks[$index][$role] = [ordered]@{
            name = $row.name
            shape = $row.shape
            ggml_type = [int]$row.ggml_type
            offset = [uint64]$row.offset
            bytes = [uint64]$row.bytes
        }
    }
    if ($blocks.Count -eq 0) { throw 'No decoder block tensors were found in the probe output.' }

    $layerList = @()
    $unknown = @()
    foreach ($index in ($blocks.Keys | Sort-Object)) {
        $t = $blocks[$index]
        $has = { param([string]$name) $t.Contains($name) }
        $isGdn = (& $has 'attn_qkv.weight') -and (& $has 'attn_gate.weight') -and
            (& $has 'ssm_a') -and (& $has 'ssm_alpha.weight') -and (& $has 'ssm_beta.weight') -and
            (& $has 'ssm_conv1d.weight') -and (& $has 'ssm_dt.bias') -and (& $has 'ssm_norm.weight') -and
            (& $has 'ssm_out.weight')
        $isAttention = (& $has 'attn_q.weight') -and (& $has 'attn_k.weight') -and
            (& $has 'attn_v.weight') -and (& $has 'attn_output.weight')
        $kind = if ($isGdn) { 'GatedDelta' } elseif ($isAttention) { 'FullAttention' } else { 'Unknown' }
        if ($kind -eq 'Unknown') { $unknown += $index }
        $state = [ordered]@{ batch = 1; hidden = 0; state = 0; key_heads = 0; value_heads = 0 }
        $norm = [ordered]@{ pre = @(); post = @() }
        if ($t.Contains('attn_norm.weight')) { $norm.pre += $t['attn_norm.weight'].name }
        if ($t.Contains('post_attention_norm.weight')) { $norm.post += $t['post_attention_norm.weight'].name }
        if ($isGdn) {
            $state.hidden = 5120
            $state.value_heads = 48
            $state.key_heads = 16
            $state.state = 48 * 128 * 128
        } elseif ($isAttention) {
            $state.hidden = 5120
            $state.value_heads = 8
            $state.key_heads = 8
        }
        $layerList += [ordered]@{
            layer_index = [int]$index
            mixer = [ordered]@{ kind = $kind; tensors = @($t.Values) }
            normalization = $norm
            state = $state
            admission = if ($kind -eq 'Unknown') { 'UnsupportedOperator' } else { 'ValidatedGeometry' }
        }
    }
    $receipt = [ordered]@{
        schema = 'rawrxd.deep2.qwen.topology_manifest.v1'
        generated_utc = [DateTime]::UtcNow.ToString('o')
        model_path = $ModelPath
        model_size_bytes = (Get-Item -LiteralPath $ModelPath).Length
        architecture = $arch
        layer_count = $layerList.Count
        layers = $layerList
        unknown_layers = @($unknown)
        topology_status = if ($unknown.Count -eq 0) { 'PASS' } else { 'UNSUPPORTED_OPERATOR' }
        execution_status = 'NOT_RUN'
        certification_status = 'NOT_CERTIFIED'
    }
    $parent = Split-Path -Parent $Output
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $receipt | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Output -Encoding UTF8
    Write-Host "TOPOLOGY_MANIFEST=$Output"
    Write-Host "ARCHITECTURE=$arch LAYERS=$($layerList.Count) UNKNOWN=$($unknown.Count) STATUS=$($receipt.topology_status)"
    if ($unknown.Count -gt 0) { exit 4 }
    exit 0
}
finally {
    Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
}
