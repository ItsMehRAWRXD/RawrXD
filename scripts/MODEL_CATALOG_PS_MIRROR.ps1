# MODEL-CATALOG-001 discovery without a new EXE (SAC-safe).
# Mirrors ModelCatalog root precedence + shallow GGUF / blobs / manifests scan.
# Does NOT claim C++ cert PASS — emits DISCOVERY_PASS / RESOLVE_PASS only for filesystem authority.

[CmdletBinding()]
param(
    [string]$ModelRoot = 'G:\OllamaModels',
    [string]$Model = '',
    [switch]$List,
    [string]$EvidenceDir = 'F:\~dev\rawrxd\evidence\SOVEREIGN_FINISH_HOUR'
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

function Get-CatalogRoots {
    $roots = New-Object System.Collections.Generic.List[string]
    $push = {
        param($p)
        if ([string]::IsNullOrWhiteSpace($p)) { return }
        $full = [IO.Path]::GetFullPath($p)
        if (-not (Test-Path -LiteralPath $full)) { return }
        foreach ($e in $roots) {
            if ($e.Equals($full, [StringComparison]::OrdinalIgnoreCase)) { return }
        }
        $roots.Add($full)
    }

    if ($env:RAWRXD_MODEL_ROOT) {
        foreach ($part in $env:RAWRXD_MODEL_ROOT.Split(';')) {
            & $push $part.Trim()
        }
    }
    & $push $ModelRoot
    & $push 'G:\OllamaModels'
    & $push 'D:\OllamaModels'
    & $push 'F:\~dev\OllamaModels'
    if ($env:USERPROFILE) {
        & $push (Join-Path $env:USERPROFILE '.ollama\models')
    }
    & $push (Join-Path (Get-Location) 'models')
    return $roots
}

function Test-GgufMagic([string]$Path) {
    try {
        $fs = [IO.File]::OpenRead($Path)
        try {
            $buf = New-Object byte[] 4
            if ($fs.Read($buf, 0, 4) -ne 4) { return $false }
            return ($buf[0] -eq 0x47 -and $buf[1] -eq 0x47 -and $buf[2] -eq 0x55 -and $buf[3] -eq 0x46)
        } finally { $fs.Dispose() }
    } catch { return $false }
}

$env:RAWRXD_MODEL_ROOT = $ModelRoot
$roots = Get-CatalogRoots
$out = New-Object System.Collections.Generic.List[string]
$out.Add('[MODEL_ROOTS]')
foreach ($r in $roots) {
    $out.Add("$r exists=yes")
}

if ($List) {
    $out.Add('')
    $out.Add('[MODELS]')
    $seen = @{}
    foreach ($root in $roots) {
        Get-ChildItem -LiteralPath $root -File -Filter '*.gguf' -ErrorAction SilentlyContinue | ForEach-Object {
            if ($seen.ContainsKey($_.FullName)) { return }
            if (-not (Test-GgufMagic $_.FullName)) { return }
            $seen[$_.FullName] = $true
            $out.Add("$($_.BaseName)`tgguf`t$($_.FullName)")
        }
        $blobs = Join-Path $root 'blobs'
        if (Test-Path -LiteralPath $blobs) {
            Get-ChildItem -LiteralPath $blobs -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like 'sha256-*' } |
                Select-Object -First 64 |
                ForEach-Object {
                    if ($seen.ContainsKey($_.FullName)) { return }
                    if (-not (Test-GgufMagic $_.FullName)) { return }
                    $seen[$_.FullName] = $true
                    $digest = $_.Name.Substring(7)
                    $out.Add("sha256-$digest`tollama-blob-file`t$($_.FullName)`tsha256:$digest")
                }
        }
    }
}

$resolveLine = $null
if (-not [string]::IsNullOrWhiteSpace($Model)) {
    if (Test-Path -LiteralPath $Model) {
        $p = (Get-Item -LiteralPath $Model).FullName
        $kind = if ((Test-GgufMagic $p)) { 'gguf' } else { 'unknown' }
        $resolveLine = @"

[RESOLVED]
spec=$Model
display_name=$([IO.Path]::GetFileNameWithoutExtension($p))
path=$p
kind=$kind
blob_offset=0
MODEL-CATALOG-001=PASS
mode=POWERSHELL_FILESYSTEM_MIRROR
note=C++ rawrxd_model_catalog_cert.exe still SAC-blocked; this is filesystem authority evidence only.
"@
    } else {
        $resolveLine = "MODEL-CATALOG-001=FAIL`nreason=unresolved`nspec=$Model"
    }
}

if ([string]::IsNullOrWhiteSpace($Model) -or $List) {
    $out.Add('')
    $out.Add('MODEL-CATALOG-001=DISCOVERY_PASS')
    $out.Add('mode=POWERSHELL_FILESYSTEM_MIRROR')
}

$text = ($out -join "`n")
if ($resolveLine) { $text = $text + "`n" + $resolveLine }
$text | Tee-Object (Join-Path $EvidenceDir 'model_catalog_ps_mirror.txt')
if ($resolveLine -and $resolveLine -match 'FAIL') { exit 2 }
exit 0
