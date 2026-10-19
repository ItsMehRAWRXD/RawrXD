<#
.SYNOPSIS
    Automated Model Manifest Mapper for Local Ollama Repositories.
.DESCRIPTION
    Resolves hash signatures to create cleanly structured GGUF symlinks.
#>
param (
    [string]$TargetMappingDir = "G:\~dev\rawrxd\models",
    [string]$OllamaBaseDir = "$env:USERPROFILE\.ollama\models"
)

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "       OLLAMA MANIFEST REGISTRY EXPANSION CORE       " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

if (-not (Test-Path $TargetMappingDir)) {
    New-Item -Path $TargetMappingDir -ItemType Directory -Force | Out-Null
}

$manifestsDir = Join-Path $OllamaBaseDir "manifests\registry.ollama.ai"
$blobsDir = Join-Path $OllamaBaseDir "blobs"

if (-not (Test-Path $manifestsDir)) {
    Write-Error "[ENV_ERROR] Local Ollama installation manifests not found at $manifestsDir"
    exit 1
}

# Scan deep into the registry layout structures
$manifestFiles = Get-ChildItem -Path $manifestsDir -Recurse -File

foreach ($file in $manifestFiles) {
    try {
        # Parse the underlying metadata payload mapping layers safely
        $manifestJson = Get-Content -Raw -Path $file.FullName | ConvertFrom-Json
        
        # Isolate the definitive model weights config layers
        $modelLayer = $manifestJson.layers | Where-Object { $_.mediaType -like "*model*" } | Select-Object -First 1
        
        if ($null -ne $modelLayer) {
            $rawHash = $modelLayer.digest
            # Strip out the sha256 identifier syntax flag to locate the tracking file layout
            $cleanHash = $rawHash -replace "sha256:", ""
            $sourceBlobPath = Join-Path $blobsDir "sha256-$cleanHash"
            
            if (Test-Path $sourceBlobPath) {
                # Format a clean, scannable model name string for your engine loaders
                $friendlyName = ($file.Directory.Name + "_" + $file.Name) -replace ":", "_" -replace "-", "_"
                $targetSymlinkPath = Join-Path $TargetMappingDir "$friendlyName.gguf"
                
                if (-not (Test-Path $targetSymlinkPath)) {
                    Write-Host "[MAPPING] Creating symlink: $friendlyName.gguf -> $sourceBlobPath" -ForegroundColor Green
                    try {
                        New-Item -ItemType SymbolicLink -Path $targetSymlinkPath -Target $sourceBlobPath -Force | Out-Null
                    } catch {
                        Write-Host "[WARN] Could not create symlink (requires admin): $friendlyName.gguf" -ForegroundColor Yellow
                        Write-Host "  -> Manual step: mklink /D `"$targetSymlinkPath`" `"$sourceBlobPath`"" -ForegroundColor Gray
                    }
                } else {
                    Write-Host "[PRESENT] $friendlyName.gguf structural link already allocated." -ForegroundColor Gray
                }
            }
        }
    } catch {
        # Gracefully step over un-parseable custom remote model tags
        continue;
    }
}
Write-Host "[SUCCESS] Model caching pool mapping sync completed cleanly.`n" -ForegroundColor Green