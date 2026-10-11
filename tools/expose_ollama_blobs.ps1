param(
    [string]$ManifestRoot = "F:\OllamaModels\manifests",
    [string]$BlobRoot     = "F:\OllamaModels\blobs",
    [string]$OutDir       = "F:\models\gguf",
    [int64]$MinBytes      = 16MB,
    [switch]$Verify
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$manifests = Get-ChildItem $ManifestRoot -Recurse -File -ErrorAction SilentlyContinue
$results = @()
$skipped = @()

foreach ($m in $manifests) {
    $rel = $m.FullName.Substring($ManifestRoot.Length + 1)
    # registry.ollama.ai\<namespace>\<name>\<tag>   or   hf.co\<org>\<repo>\<tag>
    $parts = $rel -split '[\\/]'
    $tag = $parts[-1]
    $name = $parts[-2]
    $ns   = $parts[-3]

    try { $j = Get-Content $m.FullName -Raw | ConvertFrom-Json }
    catch { $skipped += [pscustomobject]@{model="$ns/$name"; tag=$tag; reason="unparseable manifest"}; continue }

    if (-not $j.layers) { $skipped += [pscustomobject]@{model="$ns/$name"; tag=$tag; reason="no layers"}; continue }

    $weightLayers = @($j.layers | Where-Object { $_.mediaType -eq 'application/vnd.ollama.image.model' })
    if ($weightLayers.Count -eq 0) {
        $skipped += [pscustomobject]@{model="$ns/$name"; tag=$tag; reason="no local model layer (cloud or template only)"}
        continue
    }

    $idx = 0
    foreach ($layer in $weightLayers) {
        $idx++
        $digest = $layer.digest
        if (-not $digest) { continue }
        $hex = ($digest -split ':',2)[1]
        $blob = Join-Path $BlobRoot "sha256-$hex"
        $size = [int64]$layer.size

        if (-not (Test-Path $blob)) {
            $skipped += [pscustomobject]@{model="$ns/$name"; tag=$tag; reason="blob missing $hex"}
            continue
        }
        if ($size -lt $MinBytes) {
            $skipped += [pscustomobject]@{model="$ns/$name"; tag=$tag; reason="layer too small ($([math]::Round($size/1MB,2)) MB)"}
            continue
        }

        $safeNs  = ($ns  -replace '[^A-Za-z0-9._-]','_')
        $safeNm  = ($name -replace '[^A-Za-z0-9._-]','_')
        $safeTag = ($tag -replace '[^A-Za-z0-9._-]','_')
        $suffix  = if ($weightLayers.Count -gt 1) { ".$idx" } else { "" }
        $outName = "{0}__{1}__{2}{3}.gguf" -f $safeNs, $safeNm, $safeTag, $suffix
        $outPath = Join-Path $OutDir $outName

        $created = $false
        if (Test-Path $outPath) {
            $existing = (Get-Item $outPath)
            if ([int64]$existing.Length -eq $size) {
                $created = $true   # already linked
            } else {
                Remove-Item $outPath -Force
                New-Item -ItemType HardLink -Path $outPath -Target $blob -ErrorAction Stop | Out-Null
                $created = $true
            }
        } else {
            try {
                New-Item -ItemType HardLink -Path $outPath -Target $blob -ErrorAction Stop | Out-Null
                $created = $true
            } catch {
                New-Item -ItemType SymbolicLink -Path $outPath -Target $blob -ErrorAction Stop | Out-Null
                $created = $true
            }
        }

        $arch = $null; $magic = $null; $ok = $false
        if ($Verify -and $created) {
            try {
                $fs = [System.IO.File]::OpenRead($outPath)
                $buf = New-Object byte[] 8
                $fs.Read($buf,0,4) | Out-Null
                $magic = [Text.Encoding]::ASCII.GetString($buf,0,4)
                $fs.Close()
                $ok = ($magic -eq 'GGUF')
            } catch { $ok = $false }
        }

        $results += [pscustomobject]@{
            model      = "$ns/$name"
            tag        = $tag
            layer      = "$idx/$($weightLayers.Count)"
            blob_sha256= $hex
            bytes      = $size
            gib        = [math]::Round($size/1GB, 2)
            gguf_path  = $outPath
            linked     = $created
            gguf_magic = $magic
            gguf_ok    = $ok
        }
    }
}

# Report
Write-Output "=== Ollama blob -> GGUF exposure ==="
Write-Output "manifests scanned : $($manifests.Count)"
Write-Output "model layers linked: $($results.Count)"
Write-Output "total size         : $([math]::Round((($results | Measure-Object -Property bytes -Sum).Sum)/1GB,2)) GiB (hardlinked, no extra disk)"
if ($Verify) {
    $vok = @($results | Where-Object { $_.gguf_ok }).Count
    Write-Output "GGUF magic verified: $vok of $($results.Count)"
}
Write-Output ""
Write-Output "--- linked models ---"
$results | Sort-Object model, tag | ForEach-Object {
    "  {0,-58} {1,-14} {2,9} GiB  {3}" -f $_.model, $_.tag, $_.gib, $(if($_.gguf_ok){"GGUF"}elseif($Verify){"NOT-GGUF"}else{"-"})
}

$sk = $skipped | Sort-Object model -Unique
Write-Output ""
Write-Output "--- skipped ($($sk.Count)) ---"
$sk | Group-Object reason | ForEach-Object { "  $($_.Count) x $($_.Name)" }

$manifest = [pscustomobject]@{
    generated = (Get-Date -Format o)
    out_dir   = $OutDir
    blob_root = $BlobRoot
    manifests_scanned = $manifests.Count
    layers_linked = $results.Count
    total_bytes = ($results | Measure-Object -Property bytes -Sum).Sum
    gguf_verified = $Verify
    files = $results
    skipped = $sk
}
$manifest | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $OutDir "manifest.json")
Write-Output ""
Write-Output "manifest: $(Join-Path $OutDir 'manifest.json')"
