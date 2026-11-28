#requires -Version 5.1
<#
.SYNOPSIS
  Extracts quantization from GGUF tensor names and patches models/registry.json
  without re-hashing (M-CFG-04).
#>
[CmdletBinding()]
param(
    [string]$ModelsDir,
    [string]$RegistryPath
)
$ErrorActionPreference = 'Stop'
if (-not $ModelsDir) {
    $base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $ModelsDir = Join-Path $base '..\models'
    $RegistryPath = Join-Path $ModelsDir 'registry.json'
}

function Get-QuantFromName {
    param([string]$Name)
    foreach ($q in @('Q8_K','Q6_K','Q5_K','Q4_K','Q3_K','Q2_K','Q5_0','Q4_0','Q8_0','F16','F32')) {
        if ($Name -match $q) { return $q }
    }
    return 'unknown'
}

function Read-TensorQuant {
    param([string]$Path)
    $fs = [System.IO.File]::OpenRead($Path)
    try {
        $br = New-Object System.IO.BinaryReader($fs)
        if ([System.Text.Encoding]::ASCII.GetString($br.ReadBytes(4)) -ne 'GGUF') { return 'unknown' }
        $null = $br.ReadUInt32()
        $tensorCount = $br.ReadUInt64()
        $kvCount = $br.ReadUInt64()
        for ($i = 0; $i -lt $kvCount; $i++) {
            $klen = $br.ReadUInt64(); if ($klen -gt 4096) { return 'unknown' }
            $null = $br.ReadBytes([int]$klen)
            $type = $br.ReadUInt32()
            switch ($type) {
                0 { $null = $br.ReadByte() } 1 { $null = $br.ReadByte() }
                2 { $null = $br.ReadUInt16() } 3 { $null = $br.ReadInt16() }
                4 { $null = $br.ReadUInt32() } 5 { $null = $br.ReadInt32() }
                6 { $null = $br.ReadSingle() } 7 { $null = $br.ReadByte() }
                8 { $n = $br.ReadUInt64(); if ($n -gt 65536) { return 'unknown' }; $null = $br.ReadBytes([int]$n) }
                9 {
                    $elem = $br.ReadUInt32()
                    $count = $br.ReadUInt64()
                    switch ($elem) {
                        0 { $null = $br.ReadBytes([int]$count) }
                        1 { $null = $br.ReadBytes([int]$count) }
                        2 { $null = $br.ReadBytes([int]$count * 2) }
                        3 { $null = $br.ReadBytes([int]$count * 2) }
                        4 { $null = $br.ReadBytes([int]$count * 4) }
                        5 { $null = $br.ReadBytes([int]$count * 4) }
                        6 { $null = $br.ReadBytes([int]$count * 4) }
                        7 { $null = $br.ReadBytes([int]$count) }
                        8 { for ($s = 0; $s -lt $count; $s++) { $sl = $br.ReadUInt64(); $null = $br.ReadBytes([int]$sl) } }
                        10 { $null = $br.ReadBytes([int]$count * 8) }
                        11 { $null = $br.ReadBytes([int]$count * 8) }
                        12 { $null = $br.ReadBytes([int]$count * 8) }
                        default { return 'unknown' }
                    }
                }
                10 { $null = $br.ReadUInt64() } 11 { $null = $br.ReadInt64() }
                12 { $null = $br.ReadDouble() }
                default { return 'unknown' }
            }
        }
        for ($t = 0; $t -lt $tensorCount; $t++) {
            $nlen = $br.ReadUInt64()
            if ($nlen -gt 4096) { return 'unknown' }
            $name = [System.Text.Encoding]::UTF8.GetString($br.ReadBytes([int]$nlen))
            $dims = $br.ReadUInt32()
            $null = $br.ReadBytes([int]$dims * 8)
            $ttype = $br.ReadUInt32()
            $null = $br.ReadUInt64()
            $q = switch ($ttype) {
                0 { 'F32' } 1 { 'F16' } 2 { 'Q4_0' } 3 { 'Q4_1' }
                6 { 'Q5_0' } 7 { 'Q5_1' } 8 { 'Q8_0' } 9 { 'Q8_1' }
                10 { 'Q2_K' } 11 { 'Q3_K' } 12 { 'Q4_K' } 13 { 'Q5_K' }
                14 { 'Q6_K' } 15 { 'Q8_K' }
                default { 'unknown' }
            }
            if ($q -ne 'unknown') { return $q }
        }
        return 'unknown'
    } finally { $fs.Dispose() }
}

$doc = Get-Content -LiteralPath $RegistryPath -Raw | ConvertFrom-Json
$patched = 0
foreach ($m in $doc.models) {
    if (-not $m.available) { continue }
    $full = Join-Path (Split-Path $RegistryPath -Parent) (Split-Path $m.path -Leaf)
    if (-not (Test-Path $full)) { continue }
    $q = Read-TensorQuant $full
    if ($q -eq 'unknown') {
        $fs = [System.IO.File]::OpenRead($full)
        try {
            $buf = New-Object byte[] (16 * 1024 * 1024)
            $n = $fs.Read($buf, 0, $buf.Length)
            $head = [System.Text.Encoding]::ASCII.GetString($buf, 0, $n)
            $m = [regex]::Match($head, 'Q\d_[A-Z0-9]+')
            if ($m.Success) { $q = $m.Value }
            elseif ($head -match 'F16') { $q = 'F16' }
            elseif ($head -match 'F32') { $q = 'F32' }
        } finally { $fs.Dispose() }
    }
    if ($q -ne 'unknown' -and $m.quantization -eq 'unknown') { $m.quantization = $q; $patched++ }
}
$doc | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $RegistryPath -Encoding UTF8
Write-Host "Patched quantization for $patched entries"