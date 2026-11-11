# Extract local Ollama models as GGUF files by hardlinking the model-layer
# blob from Ollama's manifest store (same volume, so no disk is duplicated).
$ErrorActionPreference = "Continue"
$blobDir = "F:\OllamaModels\blobs"
$outDir = "F:\rawrxd\models"
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

function Find-Manifest([string]$name) {
    # library models: registry.ollama.ai/library/<name>/<tag|latest>
    $parts = $name -split ":"
    $base = $parts[0]; $tag = if ($parts.Count -gt 1) { $parts[1] } else { "latest" }
    $cands = @(
        "F:\OllamaModels\manifests\registry.ollama.ai\library\$base\$tag",
        "F:\OllamaModels\manifests\registry.ollama.ai\$base\$tag"
    )
    foreach ($c in $cands) { if (Test-Path $c) { return $c } }
    # fall back to a recursive search on the base name
    $hit = Get-ChildItem -LiteralPath "F:\OllamaModels\manifests" -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match [regex]::Escape($base) -and $_.Name -eq $tag } | Select-Object -First 1
    if ($hit) { return $hit.FullName }
    return $null
}

function Extract-Gguf([string]$name) {
    $mf = Find-Manifest $name
    if (-not $mf) { Write-Output "$name : MANIFEST NOT FOUND"; return }
    $m = Get-Content -LiteralPath $mf -Raw | ConvertFrom-Json
    $layer = $m.layers | Where-Object { $_.mediaType -eq "application/vnd.ollama.image.model" } | Select-Object -First 1
    if (-not $layer) { Write-Output "$name : NO MODEL LAYER"; return }
    $digest = $layer.digest -replace "sha256:", ""
    $blob = Join-Path $blobDir "sha256-$digest"
    if (-not (Test-Path $blob)) { Write-Output "$name : BLOB MISSING ($digest)"; return }
    $safe = ($name -replace "[^A-Za-z0-9._-]", "_")
    $out = Join-Path $outDir "$safe.gguf"
    if (Test-Path $out) { Remove-Item $out -Force }
    cmd /c "mklink /H `"$out`" `"$blob`"" | Out-Null
    if (-not (Test-Path $out)) { Write-output "$name : LINK FAILED"; return }
    $fs = [System.IO.File]::OpenRead($out)
    $buf = New-Object byte[] 8
    $fs.Read($buf, 0, 8) | Out-Null
    $fs.Close()
    $magic = [System.Text.Encoding]::ASCII.GetString($buf, 0, 4)
    $ver = [BitConverter]::ToUInt32($buf, 4)
    $ok = ($magic -eq "GGUF")
    Write-Output ("{0,-42} {1,-7} v{2} {3,8:N2} GB  -> {4}" -f $name, $magic, $ver, ((Get-Item $out).Length/1GB), (Split-Path $out -Leaf))
}

$targets = @(
    "nemotron-3.5-lightning:30b",
    "nemotron-3-nano:4b",
    "deepseek-r1:32b",
    "qwen2.5-coder:1.5b-base",
    "gemma3:latest",
    "starcoder2:15b",
    "deepseek-coder-v2:16b",
    "gpt-oss:latest",
    "ornith-1.5:35b",
    "bigdaddygnative:latest",
    "kiminoto/T0.0.1:latest",
    "pdurugyan/qwen3.5-9b-deepseek-v4-flash-Q4_K_M-v_2:latest"
)
foreach ($t in $targets) { Extract-Gguf $t }
