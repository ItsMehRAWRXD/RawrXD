# ============================================================================
# resolve_ollama_models.ps1  --  RAWRXD_DEEP2_OLLAMA_MODEL_SWEEP_001
# ============================================================================
# Maps every model in `ollama list` to its local GGUF blob under the ollama
# store, so the Deep2 runtime dispatch tool can be run against each one.
//   (%USERPROFILE%\.ollama\models\)
//     manifests/registry.ollama.ai/library/<name>/<tag>   (JSON layer digests)
//     blobs/sha256-<digest>                               (the GGUF bytes)
// A model whose layers are all absent (cloud-only entries) is reported with
// NO_LOCAL_BLOB rather than silently skipped.
#
# Usage:
//   powershell -File tools\resolve_ollama_models.ps1 [-JsonOut "path"]
# ============================================================================
param(
    [string]$JsonOut = "F:\rawrxd\ollama_model_blobs.json"
)

$ErrorActionPreference = "Stop"

# Store auto-detect: the default user store can be empty while the server is
# actually pointed at a large custom store (OLLAMA_MODELS). Pick the root that
# actually holds manifests.
$storeRoots = @("F:\OllamaModels", (Join-Path $env:USERPROFILE ".ollama\models"))
$store = $null
foreach ($r in $storeRoots) {
    if (Test-Path -LiteralPath $r) {
        $n = 0
        foreach ($sub in @("manifests", "manifests-v2")) {
            $p = Join-Path $r $sub
            if (Test-Path -LiteralPath $p) {
                $n += (Get-ChildItem -LiteralPath $p -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count
            }
        }
        if ($n -gt 0) { $store = $r; Write-Host "using model store: $store ($n manifests)"; break }
    }
}
if (-not $store) { Write-Error "no ollama model store with manifests found"; exit 1 }
$blobs = Join-Path $store "blobs"

# `ollama list --format json` would be ideal but older builds lack it; parse
# the table and keep whatever it gives us.
$models = @()
try {
    $listRaw = & ollama list 2>$null
} catch {
    Write-Error "ollama CLI not available: $_"
    exit 1
}
foreach ($line in $listRaw) {
    if ($line -match '^\s*NAME\s+ID\s+SIZE') { continue }
    if ($line -notmatch '^\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$') { continue }
    $models += [pscustomobject]@{
        name = $matches[1]; id = $matches[2]; size = $matches[3]; modified = $matches[4]
    }
}
Write-Host "ollama models: $($models.Count)"

function Resolve-Blob([string]$modelName) {
    # Split namespace/name:tag the way the manifest tree is laid out.
    $tag = "latest"
    $base = $modelName
    if ($base -match '^(.*):([^:/]+)$') { $base = $matches[1]; $tag = $matches[2] }
    $parts = $base -split '/'
    $tail = ($parts -join '/')
    # Look in both manifest layouts (v2: registry.ollama.ai/library/...,
    # v1: hf.co/... or custom namespaces). The path tail is "<ns>/<name>/<tag>"
    # or "<name>/<tag>".
    $candidates = @()
    foreach ($rootName in @("manifests-v2", "manifests")) {
        $root = Join-Path $store $rootName
        if (-not (Test-Path -LiteralPath $root)) { continue }
        # Direct: store/<root>/<ns>/<name>/<tag> and store/<root>/library/<name>/<tag>
        $candidates += (Join-Path $root $tail)
        $candidates += (Join-Path $root $tail.Replace('/','\'))
        $candidates += (Join-Path $root ("library\" + $tail.Replace('/','\')))
    }
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) {
            $blob = Read-ManifestBlob $c
            if ($blob) { return $blob }
        }
    }
    # Last resort: recursive search for a file whose path ends with the tail
    # (backslash-normalised: a forward-slash pattern never matches a path).
    $tailBs = $tail.Replace('/', '\')
    foreach ($rootName in @("manifests-v2", "manifests")) {
        $root = Join-Path $store $rootName
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $hit = Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -like "*\$tailBs\$tag" } |
            Select-Object -First 1
        if ($hit) {
            $blob = Read-ManifestBlob $hit.FullName
            if ($blob) { return $blob }
        }
    }
    return $null
}

function Read-ManifestBlob([string]$manifestPath) {
    try {
        $json = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    } catch {
        return $null
    }
    $layers = @()
    if ($json.layers) { $layers = @($json.layers) }
    foreach ($l in $layers) {
        $mt = "$($l.mediaType)"
        if ($mt -like "*image.model*") {
            $digest = "$($l.digest)" -replace '^sha256:', ''
            if (-not $digest) { continue }
            $blob = Join-Path $blobs ("sha256-" + $digest)
            if (Test-Path -LiteralPath $blob) {
                return [pscustomobject]@{ blob = $blob; size = (Get-Item -LiteralPath $blob).Length }
            }
            return $null   # manifest present but blob missing (purged)
        }
    }
    return $null
}

$results = @()
foreach ($m in $models) {
    $r = Resolve-Blob $m.name
    if ($r) {
        $results += [pscustomobject]@{
            name = $m.name; blob = $r.blob; blobSize = $r.size; state = "LOCAL_GGUF"
        }
    } else {
        $results += [pscustomobject]@{
            name = $m.name; blob = $null; blobSize = 0; state = "NO_LOCAL_BLOB"
        }
    }
}

$results | Sort-Object state, blobSize | Format-Table -AutoSize name, state, blobSize
$results | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $JsonOut -Encoding utf8
Write-Host "wrote $JsonOut"
$localCount = ($results | Where-Object { $_.state -eq "LOCAL_GGUF" }).Count
$noBlob = ($results | Where-Object { $_.state -eq "NO_LOCAL_BLOB" }).Count
Write-Host "LOCAL_GGUF=$localCount NO_LOCAL_BLOB=$noBlob"
