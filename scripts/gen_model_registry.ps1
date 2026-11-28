#requires -Version 5.1
<#
.SYNOPSIS
  Regenerates models/registry.json and models/acquisition.json from the GGUF
  files that are actually present on disk (M-CFG-04 / M-CFG-08).
  No external dependencies. Streams SHA-256 so large models do not load into RAM.
#>
[CmdletBinding()]
param(
    [string]$ModelsDir,
    [string]$RegistryPath,
    [string]$AcquisitionPath
)
$ErrorActionPreference = 'Stop'
if (-not $ModelsDir) {
    $base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $ModelsDir = Join-Path $base '..\models'
    $RegistryPath = Join-Path $ModelsDir 'registry.json'
    $AcquisitionPath = Join-Path $ModelsDir 'acquisition.json'
}

function Read-GgufHeader {
    param([string]$Path)
    $fs = [System.IO.File]::OpenRead($Path)
    try {
        $br = New-Object System.IO.BinaryReader($fs)
        $magic = [System.Text.Encoding]::ASCII.GetString($br.ReadBytes(4))
        if ($magic -ne 'GGUF') { return @{ valid = $false; error = 'not GGUF' } }
        $version = $br.ReadUInt32()
        $tensorCount = $br.ReadUInt64()
        $kvCount = $br.ReadUInt64()
        $arch = ''
        $context = 0
        for ($i = 0; $i -lt $kvCount; $i++) {
            $klen = $br.ReadUInt64()
            if ($klen -gt 4096) { break }
            $key = [System.Text.Encoding]::UTF8.GetString($br.ReadBytes([int]$klen))
            $type = $br.ReadUInt32()
            switch ($type) {
                0 { $null = $br.ReadByte() }
                1 { $null = $br.ReadByte() }
                2 { $null = $br.ReadUInt16() }
                3 { $null = $br.ReadInt16() }
                4 { $v = $br.ReadUInt32(); if ($key -like '*context_length*') { $context = $v } }
                5 { $null = $br.ReadInt32() }
                6 { $null = $br.ReadSingle() }
                7 { $null = $br.ReadByte() }
                8 { $slen = $br.ReadUInt64(); if ($slen -gt 65536) { break }; $s = [System.Text.Encoding]::UTF8.GetString($br.ReadBytes([int]$slen)); if ($key -eq 'general.architecture') { $arch = $s } }
                9 { $n = $br.ReadUInt32(); $null = $br.ReadBytes([int]$n * 4) }
                10 { $v = $br.ReadUInt64(); if ($key -like '*context_length*') { $context = [uint32]$v } }
                11 { $null = $br.ReadInt64() }
                12 { $null = $br.ReadDouble() }
                default { return @{ valid = $false; error = "unknown value type $type" } }
            }
        }
        return @{ valid = $true; version = $version; tensors = $tensorCount; architecture = $arch; contextLength = $context }
    } finally {
        $fs.Dispose()
    }
}

function Get-Sha256 {
    param([string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = [System.IO.File]::OpenRead($Path)
    try {
        return [System.BitConverter]::ToString($sha.ComputeHash($fs)).Replace('-', '').ToLowerInvariant()
    } finally {
        $fs.Dispose()
        $sha.Dispose()
    }
}

$legacy = @{}
if (Test-Path $RegistryPath) {
    try {
        $old = Get-Content -LiteralPath $RegistryPath -Raw | ConvertFrom-Json
        foreach ($m in $old.models) { $legacy[$m.path] = $m }
    } catch { }
}

$entries = @()
$shards = @{}
Get-ChildItem -LiteralPath $ModelsDir -Filter '*.gguf' -File | Sort-Object Name | ForEach-Object {
    $file = $_
    Write-Host "Hashing $($file.Name) ($([math]::Round($file.Length / 1GB, 2)) GB)..."
    $header = Read-GgufHeader -Path $file.FullName
    $sha = Get-Sha256 -Path $file.FullName
    $rel = "models/$($file.Name)"
    $quant = 'unknown'
    if ($file.Name -match 'Q8_K') { $quant = 'Q8_K' }
    elseif ($file.Name -match 'Q6_K') { $quant = 'Q6_K' }
    elseif ($file.Name -match 'Q5_K') { $quant = 'Q5_K' }
    elseif ($file.Name -match 'Q4_K') { $quant = 'Q4_K' }
    elseif ($file.Name -match 'Q3_K') { $quant = 'Q3_K' }
    elseif ($file.Name -match 'Q2_K') { $quant = 'Q2_K' }
    elseif ($file.Name -match 'Q4_0') { $quant = 'Q4_0' }
    elseif ($file.Name -match 'Q8_0') { $quant = 'Q8_0' }
    elseif ($file.Name -match 'F16') { $quant = 'F16' }
    elseif ($file.Name -match 'F32') { $quant = 'F32' }

    $entry = [ordered]@{
        id = ($file.BaseName -replace '[^a-zA-Z0-9_.-]', '_')
        name = $file.BaseName
        path = $rel
        backend_type = 'native'
        is_local = $true
        available = $true
        size_bytes = $file.Length
        sha256 = $sha
        quantization = $quant
        architecture = if ($header.architecture) { $header.architecture } else { 'unknown' }
        context_window = $header.contextLength
        tensor_count = $header.tensors
        shard_of = $null
        shard_index = $null
        shard_total = $null
        complete = $true
        compatibility = [ordered]@{
            backend = 'native'
            min_vram_bytes = $file.Length
            requires_vulkan = $false
            status = if ($header.valid) { 'verified' } else { 'header_error' }
        }
    }
    if ($file.Name -match '-(\d{5})-of-(\d{5})\.gguf$') {
        $entry.shard_index = [int]$Matches[1]
        $entry.shard_total = [int]$Matches[2]
        $entry.shard_of = ($file.Name -replace '-\d{5}-of-\d{5}\.gguf$', '')
    }
    $entries += [pscustomobject]$entry
}

# Preserve legacy entries that are not on disk, marked unavailable.
foreach ($path in $legacy.Keys) {
    if (-not (Test-Path (Join-Path (Split-Path $ModelsDir -Parent) $path))) {
        $m = $legacy[$path]
        $entries += [pscustomobject][ordered]@{
            id = $m.id; name = $m.name; path = $m.path; backend_type = $m.backend_type
            is_local = $true; available = $false; size_bytes = 0; sha256 = $null
            quantization = $m.quantization; architecture = 'unknown'; context_window = $m.context_window
            tensor_count = 0; shard_of = $null; shard_index = $null; shard_total = $null
            complete = $false
            compatibility = [ordered]@{ backend = 'native'; min_vram_bytes = 0; requires_vulkan = $false; status = 'missing_on_disk' }
        }
    }
}

$registry = [ordered]@{
    version = '15.0.0'
    generated_by = 'scripts/gen_model_registry.ps1'
    generated_at = (Get-Date).ToString('o')
    model_count = $entries.Count
    available_count = ($entries | Where-Object { $_.available }).Count
    models = $entries
}
$registry | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $RegistryPath -Encoding UTF8

$acq = [ordered]@{
    version = '1.0.0'
    resumable_downloads = $true
    verify_before_register = $true
    entries = @($entries | Where-Object { $_.available } | ForEach-Object {
        [ordered]@{
            path = $_.path
            sha256 = $_.sha256
            size_bytes = $_.size_bytes
            source_url = ''
            revision = ''
            license = 'unknown'
            shards_complete = $_.complete
        }
    })
}
$acq | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $AcquisitionPath -Encoding UTF8

Write-Host "Registry: $($entries.Count) entries ($($registry.available_count) available)"
Write-Host "Wrote $RegistryPath"
Write-Host "Wrote $AcquisitionPath"