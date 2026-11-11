# RawrXD Model Registry CLI
# Command-line interface for managing GGUF models and their metadata

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("list", "add", "remove", "info", "download", "verify", "import", "export", "search")]
    [string]$Command = "list",
    
    [string]$ModelId,
    [string]$ModelPath,
    [string]$OutputPath,
    [string]$Source,
    [string]$Filter,
    [switch]$Force,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# Registry configuration
$RegistryConfig = @{
    RegistryPath = "$env:LOCALAPPDATA\RawrXD\ModelRegistry"
    ModelsDir = "$env:LOCALAPPDATA\RawrXD\Models"
    CacheDir = "$env:LOCALAPPDATA\RawrXD\ModelCache"
    MaxCacheSizeGB = 100
    SupportedFormats = @(".gguf", ".ggml", ".bin")
    DefaultQuantization = "Q4_K_M"
}

# Model metadata schema
$ModelSchema = @{
    RequiredFields = @("id", "name", "format", "size", "parameters")
    OptionalFields = @("description", "tags", "quantization", "context_length", "license", "source_url", "sha256", "added_date", "last_used")
}

# Registry state
$script:Registry = @{}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[✗] $Message" -ForegroundColor Red }
function Write-Verbose { param([string]$Message) if ($Verbose) { Write-Host "[v] $Message" -ForegroundColor Gray } }

function Initialize-Registry {
    Write-Status "Initializing model registry..."
    
    # Create directories
    foreach ($dir in @($RegistryConfig.RegistryPath, $RegistryConfig.ModelsDir, $RegistryConfig.CacheDir)) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Verbose "Created directory: $dir"
        }
    }
    
    # Load existing registry
    $registryFile = "$($RegistryConfig.RegistryPath)\registry.json"
    if (Test-Path $registryFile) {
        $script:Registry = Get-Content $registryFile | ConvertFrom-Json -AsHashtable
        Write-Verbose "Loaded registry with $($script:Registry.Count) models"
    } else {
        $script:Registry = @{}
        Write-Verbose "Created new empty registry"
    }
    
    Write-Success "Registry initialized"
}

function Save-Registry {
    $registryFile = "$($RegistryConfig.RegistryPath)\registry.json"
    $script:Registry | ConvertTo-Json -Depth 10 | Out-File $registryFile
    Write-Verbose "Registry saved to $registryFile"
}

function Get-ModelHash {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) { return $null }
    
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($FilePath)
    $hash = $sha256.ComputeHash($stream)
    $stream.Close()
    
    return [BitConverter]::ToString($hash).Replace("-", "").ToLower()
}

function Get-ModelMetadata {
    param([string]$FilePath)
    
    $fileInfo = Get-Item $FilePath
    $metadata = @{
        id = [System.IO.Path]::GetFileNameWithoutExtension($fileInfo.Name)
        name = $fileInfo.BaseName
        format = $fileInfo.Extension.ToLower()
        size = $fileInfo.Length
        size_human = "{0:N2} GB" -f ($fileInfo.Length / 1GB)
        added_date = Get-Date -Format "o"
        last_used = $null
        path = $FilePath
    }
    
    # Try to extract GGUF metadata
    if ($fileInfo.Extension -eq ".gguf") {
        try {
            # Use gguf-py or similar tool to extract metadata
            # For now, we'll use placeholder values
            $metadata.quantization = "Unknown"
            $metadata.parameters = "Unknown"
            $metadata.context_length = 4096
        } catch {
            Write-Verbose "Could not extract GGUF metadata: $_"
        }
    }
    
    return $metadata
}

function Invoke-ListCommand {
    param([string]$Filter)
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Model Registry" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($script:Registry.Count -eq 0) {
        Write-Host "No models registered." -ForegroundColor Yellow
        Write-Host "Use 'model-registry-cli.ps1 add -ModelPath \path\to\model.gguf' to add models." -ForegroundColor Gray
        return
    }
    
    $models = $script:Registry.Values
    
    if ($Filter) {
        $models = $models | Where-Object { 
            $_.id -like "*$Filter*" -or 
            $_.name -like "*$Filter*" -or
            ($_.tags -and $_.tags -contains $Filter)
        }
    }
    
    # Display as table
    $models | Select-Object id, name, format, size_human, quantization, @{N="Added";E={$_.added_date.Substring(0,10)}} | 
        Format-Table -AutoSize
    
    Write-Host "Total: $($models.Count) models" -ForegroundColor Gray
}

function Invoke-AddCommand {
    param([string]$Path, [switch]$Force)
    
    if (-not (Test-Path $Path)) {
        Write-Error "Model file not found: $Path"
        return
    }
    
    $metadata = Get-ModelMetadata -FilePath $Path
    
    # Check if already registered
    if ($script:Registry.ContainsKey($metadata.id) -and -not $Force) {
        Write-Warning "Model '$($metadata.id)' already registered. Use -Force to update."
        return
    }
    
    # Calculate hash
    Write-Status "Calculating model hash..."
    $metadata.sha256 = Get-ModelHash -FilePath $Path
    
    # Copy to models directory
    $destPath = "$($RegistryConfig.ModelsDir)\$($fileInfo.Name)"
    if ($Path -ne $destPath) {
        Write-Status "Copying model to registry..."
        Copy-Item $Path $destPath -Force
        $metadata.path = $destPath
    }
    
    # Add to registry
    $script:Registry[$metadata.id] = $metadata
    Save-Registry
    
    Write-Success "Model '$($metadata.id)' added to registry"
    Write-Host "  Size: $($metadata.size_human)" -ForegroundColor Gray
    Write-Host "  Hash: $($metadata.sha256.Substring(0,16))..." -ForegroundColor Gray
}

function Invoke-RemoveCommand {
    param([string]$Id, [switch]$Force)
    
    if (-not $script:Registry.ContainsKey($Id)) {
        Write-Error "Model not found: $Id"
        return
    }
    
    $model = $script:Registry[$Id]
    
    if (-not $Force) {
        $confirm = Read-Host "Remove model '$Id' ($($model.size_human))? (y/N)"
        if ($confirm -ne "y") {
            Write-Status "Removal cancelled"
            return
        }
    }
    
    # Remove file
    if (Test-Path $model.path) {
        Remove-Item $model.path -Force
        Write-Verbose "Removed file: $($model.path)"
    }
    
    # Remove from registry
    $script:Registry.Remove($Id)
    Save-Registry
    
    Write-Success "Model '$Id' removed from registry"
}

function Invoke-InfoCommand {
    param([string]$Id)
    
    if (-not $script:Registry.ContainsKey($Id)) {
        Write-Error "Model not found: $Id"
        return
    }
    
    $model = $script:Registry[$Id]
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Model Information: $Id" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($prop in $model.PSObject.Properties) {
        Write-Host "$($prop.Name.PadRight(20)): $($prop.Value)" -ForegroundColor White
    }
}

function Invoke-DownloadCommand {
    param([string]$Source, [string]$ModelId)
    
    Write-Status "Downloading model from $Source..."
    
    # Support various sources
    switch -Wildcard ($Source) {
        "*huggingface.co*" {
            Write-Status "Downloading from Hugging Face..."
            # Use huggingface-cli or direct download
        }
        "*github.com*" {
            Write-Status "Downloading from GitHub..."
        }
        default {
            Write-Status "Downloading from $Source..."
        }
    }
    
    # Simulate download
    Write-Host "Downloading..." -NoNewline
    for ($i = 1; $i -le 10; $i++) {
        Start-Sleep -Milliseconds 200
        Write-Host "." -NoNewline
    }
    Write-Host ""
    
    Write-Success "Download complete (simulated)"
    Write-Warning "In production, implement actual download logic"
}

function Invoke-VerifyCommand {
    param([string]$Id)
    
    if ($Id) {
        if (-not $script:Registry.ContainsKey($Id)) {
            Write-Error "Model not found: $Id"
            return
        }
        
        $modelsToVerify = @($script:Registry[$Id])
    } else {
        $modelsToVerify = $script:Registry.Values
    }
    
    Write-Status "Verifying $($modelsToVerify.Count) model(s)..."
    
    $verified = 0
    $failed = 0
    
    foreach ($model in $modelsToVerify) {
        Write-Verbose "Verifying $($model.id)..."
        
        if (-not (Test-Path $model.path)) {
            Write-Warning "Model file missing: $($model.id)"
            $failed++
            continue
        }
        
        if ($model.sha256) {
            $currentHash = Get-ModelHash -FilePath $model.path
            if ($currentHash -ne $model.sha256) {
                Write-Warning "Hash mismatch for $($model.id)"
                $failed++
                continue
            }
        }
        
        $verified++
    }
    
    Write-Success "Verification complete: $verified verified, $failed failed"
}

function Invoke-ImportCommand {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) {
        Write-Error "Import file not found: $Path"
        return
    }
    
    $importData = Get-Content $Path | ConvertFrom-Json
    
    $imported = 0
    foreach ($model in $importData.PSObject.Properties.Value) {
        if (-not $script:Registry.ContainsKey($model.id)) {
            $script:Registry[$model.id] = $model
            $imported++
        }
    }
    
    Save-Registry
    Write-Success "Imported $imported models from $Path"
}

function Invoke-ExportCommand {
    param([string]$Path)
    
    if (-not $Path) {
        $Path = "model-registry-export-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    }
    
    $script:Registry | ConvertTo-Json -Depth 10 | Out-File $Path
    Write-Success "Registry exported to $Path"
}

function Invoke-SearchCommand {
    param([string]$Query)
    
    Write-Status "Searching for '$Query'..."
    
    $results = $script:Registry.Values | Where-Object {
        $_.id -like "*$Query*" -or
        $_.name -like "*$Query*" -or
        ($_.description -and $_.description -like "*$Query*") -or
        ($_.tags -and $_.tags -contains $Query)
    }
    
    if ($results.Count -eq 0) {
        Write-Host "No models found matching '$Query'" -ForegroundColor Yellow
        return
    }
    
    Write-Host "Found $($results.Count) model(s):" -ForegroundColor Green
    $results | Select-Object id, name, size_human | Format-Table -AutoSize
}

# Main execution
function Main {
    Write-Host "RawrXD Model Registry CLI" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-Registry
    
    switch ($Command) {
        "list" { Invoke-ListCommand -Filter $Filter }
        "add" { 
            if (-not $ModelPath) {
                Write-Error "ModelPath required for add command"
                exit 1
            }
            Invoke-AddCommand -Path $ModelPath -Force:$Force 
        }
        "remove" { 
            if (-not $ModelId) {
                Write-Error "ModelId required for remove command"
                exit 1
            }
            Invoke-RemoveCommand -Id $ModelId -Force:$Force 
        }
        "info" { 
            if (-not $ModelId) {
                Write-Error "ModelId required for info command"
                exit 1
            }
            Invoke-InfoCommand -Id $ModelId 
        }
        "download" { 
            if (-not $Source) {
                Write-Error "Source required for download command"
                exit 1
            }
            Invoke-DownloadCommand -Source $Source -ModelId $ModelId 
        }
        "verify" { Invoke-VerifyCommand -Id $ModelId }
        "import" { 
            if (-not $ModelPath) {
                Write-Error "ModelPath required for import command"
                exit 1
            }
            Invoke-ImportCommand -Path $ModelPath 
        }
        "export" { Invoke-ExportCommand -Path $OutputPath }
        "search" { 
            if (-not $Filter) {
                Write-Error "Filter required for search command"
                exit 1
            }
            Invoke-SearchCommand -Query $Filter 
        }
        default { Invoke-ListCommand }
    }
}

Main
