# RawrXD Model Manager
# Manages GGUF model downloads, validation, and configuration

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("List", "Download", "Validate", "Remove", "Info", "Configure")]
    [string]$Action = "List",
    
    [string]$ModelUrl = "",
    [string]$ModelName = "",
    [string]$ModelPath = "models",
    [string]$ConfigPath = "config/models.json",
    [switch]$Force,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# Model registry with popular models
$ModelRegistry = @{
    "llama-2-7b" = @{
        Name = "Llama 2 7B"
        Url = "https://huggingface.co/TheBloke/Llama-2-7B-GGUF/resolve/main/llama-2-7b.Q4_K_M.gguf"
        Size = "4.1 GB"
        Quantization = "Q4_K_M"
        Parameters = "7B"
        Description = "General purpose chat model"
    }
    "llama-2-13b" = @{
        Name = "Llama 2 13B"
        Url = "https://huggingface.co/TheBloke/Llama-2-13B-GGUF/resolve/main/llama-2-13b.Q4_K_M.gguf"
        Size = "7.9 GB"
        Quantization = "Q4_K_M"
        Parameters = "13B"
        Description = "Higher quality chat model"
    }
    "codellama-7b" = @{
        Name = "CodeLlama 7B"
        Url = "https://huggingface.co/TheBloke/CodeLlama-7B-GGUF/resolve/main/codellama-7b.Q4_K_M.gguf"
        Size = "4.1 GB"
        Quantization = "Q4_K_M"
        Parameters = "7B"
        Description = "Code completion and generation"
    }
    "mistral-7b" = @{
        Name = "Mistral 7B"
        Url = "https://huggingface.co/TheBloke/Mistral-7B-v0.1-GGUF/resolve/main/mistral-7b-v0.1.Q4_K_M.gguf"
        Size = "4.1 GB"
        Quantization = "Q4_K_M"
        Parameters = "7B"
        Description = "High performance general model"
    }
    "mixtral-8x7b" = @{
        Name = "Mixtral 8x7B"
        Url = "https://huggingface.co/TheBloke/Mixtral-8x7B-v0.1-GGUF/resolve/main/mixtral-8x7b-v0.1.Q4_K_M.gguf"
        Size = "26 GB"
        Quantization = "Q4_K_M"
        Parameters = "47B"
        Description = "Mixture of Experts model"
    }
    "phi-2" = @{
        Name = "Phi-2"
        Url = "https://huggingface.co/TheBloke/phi-2-GGUF/resolve/main/phi-2.Q4_K_M.gguf"
        Size = "1.6 GB"
        Quantization = "Q4_K_M"
        Parameters = "2.7B"
        Description = "Compact but powerful model"
    }
}

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Initialize-Environment {
    if (-not (Test-Path $ModelPath)) {
        New-Item -ItemType Directory -Path $ModelPath -Force | Out-Null
        Write-Success "Created models directory: $ModelPath"
    }
}

function Get-InstalledModels {
    $models = @()
    
    if (Test-Path $ModelPath) {
        $ggufFiles = Get-ChildItem -Path $ModelPath -Filter "*.gguf" -Recurse
        foreach ($file in $ggufFiles) {
            $models += @{
                Name = $file.BaseName
                Path = $file.FullName
                Size = [math]::Round($file.Length / 1GB, 2)
                Modified = $file.LastWriteTime
            }
        }
    }
    
    return $models
}

function Show-ModelList {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Available Models (Registry)" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($key in $ModelRegistry.Keys | Sort-Object) {
        $model = $ModelRegistry[$key]
        Write-Host "$key" -ForegroundColor White -NoNewline
        Write-Host " - $($model.Name)" -ForegroundColor Gray
        Write-Host "  Size: $($model.Size) | Quant: $($model.Quantization) | Params: $($model.Parameters)"
        Write-Host "  $($model.Description)"
        Write-Host ""
    }
    
    $installed = Get-InstalledModels
    if ($installed.Count -gt 0) {
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "Installed Models" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
        
        foreach ($model in $installed) {
            Write-Host "$($model.Name)" -ForegroundColor White
            Write-Host "  Path: $($model.Path)"
            Write-Host "  Size: $($model.Size) GB"
            Write-Host "  Modified: $($model.Modified)"
            Write-Host ""
        }
    }
}

function Invoke-ModelDownload {
    param(
        [string]$Url,
        [string]$Name
    )
    
    if (-not $Url) {
        Write-Error "No URL specified. Use -ModelUrl or select from registry."
        return
    }
    
    $fileName = if ($Name) { "$Name.gguf" } else { [System.IO.Path]::GetFileName($Url) }
    $outputPath = Join-Path $ModelPath $fileName
    
    if (Test-Path $outputPath) {
        if (-not $Force) {
            Write-Warning "Model already exists: $fileName"
            Write-Status "Use -Force to overwrite"
            return
        }
    }
    
    Write-Status "Downloading model..."
    Write-Status "URL: $Url"
    Write-Status "Destination: $outputPath"
    
    try {
        # Use BITS for large file downloads
        $jobName = "RawrXD-ModelDownload-$(Get-Random)"
        Start-BitsTransfer -Source $Url -Destination $outputPath -DisplayName $jobName
        
        Write-Success "Download complete: $fileName"
        
        # Validate downloaded file
        $fileInfo = Get-Item $outputPath
        Write-Status "Downloaded size: $([math]::Round($fileInfo.Length / 1MB, 2)) MB"
    }
    catch {
        Write-Error "Download failed: $_"
        if (Test-Path $outputPath) {
            Remove-Item $outputPath -Force
        }
    }
}

function Invoke-ModelValidation {
    param([string]$Name)
    
    $models = Get-InstalledModels
    
    if ($Name) {
        $models = $models | Where-Object { $_.Name -like "*$Name*" }
    }
    
    if ($models.Count -eq 0) {
        Write-Error "No models found to validate"
        return
    }
    
    Write-Status "Validating $($models.Count) model(s)..."
    
    foreach ($model in $models) {
        Write-Status "Validating: $($model.Name)"
        
        # Check file integrity
        $file = Get-Item $model.Path
        if ($file.Length -lt 1024) {
            Write-Error "Model file too small (possibly corrupted): $($model.Name)"
            continue
        }
        
        # Check GGUF magic number
        $bytes = [System.IO.File]::ReadAllBytes($model.Path)[0..3]
        $magic = [System.Text.Encoding]::ASCII.GetString($bytes)
        
        if ($magic -eq "GGUF") {
            Write-Success "Valid GGUF format: $($model.Name)"
        } else {
            Write-Error "Invalid GGUF format: $($model.Name) (Magic: $magic)"
        }
    }
}

function Invoke-ModelRemoval {
    param([string]$Name)
    
    if (-not $Name) {
        Write-Error "Model name required for removal"
        return
    }
    
    $models = Get-InstalledModels | Where-Object { $_.Name -like "*$Name*" }
    
    if ($models.Count -eq 0) {
        Write-Error "No models found matching: $Name"
        return
    }
    
    foreach ($model in $models) {
        Write-Warning "Removing: $($model.Name) ($($model.Size) GB)"
        
        if (-not $Force) {
            $confirm = Read-Host "Are you sure? (y/N)"
            if ($confirm -ne "y") {
                Write-Status "Skipped: $($model.Name)"
                continue
            }
        }
        
        Remove-Item $model.Path -Force
        Write-Success "Removed: $($model.Name)"
    }
}

function Show-ModelInfo {
    param([string]$Name)
    
    if (-not $Name) {
        Write-Error "Model name required"
        return
    }
    
    # Check registry
    if ($ModelRegistry.ContainsKey($Name)) {
        $model = $ModelRegistry[$Name]
        Write-Host "`nModel Information (Registry)" -ForegroundColor Cyan
        Write-Host "==============================" -ForegroundColor Cyan
        Write-Host "Name: $($model.Name)"
        Write-Host "Parameters: $($model.Parameters)"
        Write-Host "Quantization: $($model.Quantization)"
        Write-Host "Size: $($model.Size)"
        Write-Host "Description: $($model.Description)"
        Write-Host "Download URL: $($model.Url)"
    }
    
    # Check installed
    $installed = Get-InstalledModels | Where-Object { $_.Name -like "*$Name*" }
    if ($installed) {
        Write-Host "`nInstalled Instance" -ForegroundColor Cyan
        Write-Host "===================" -ForegroundColor Cyan
        foreach ($model in $installed) {
            Write-Host "Path: $($model.Path)"
            Write-Host "Size: $($model.Size) GB"
            Write-Host "Modified: $($model.Modified)"
            
            # Show GGUF info if available
            if (Get-Command rawrxd-cli -ErrorAction SilentlyContinue) {
                $info = & rawrxd-cli --model-info $model.Path 2>$null
                if ($info) {
                    Write-Host "`nGGUF Metadata:"
                    Write-Host $info
                }
            }
        }
    }
}

function Export-ModelConfiguration {
    $config = @{
        Models = @{}
        Settings = @{
            DefaultModel = ""
            MaxMemoryGB = 16
            AutoLoad = $true
        }
    }
    
    $installed = Get-InstalledModels
    foreach ($model in $installed) {
        $config.Models[$model.Name] = @{
            Path = $model.Path
            SizeGB = $model.Size
        }
    }
    
    $config | ConvertTo-Json -Depth 3 | Out-File $ConfigPath
    Write-Success "Model configuration exported to: $ConfigPath"
}

# Main execution
function Main {
    Write-Host "RawrXD Model Manager" -ForegroundColor Cyan
    Write-Host "====================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-Environment
    
    switch ($Action) {
        "List" { Show-ModelList }
        "Download" {
            if ($ModelRegistry.ContainsKey($ModelName)) {
                Invoke-ModelDownload -Url $ModelRegistry[$ModelName].Url -Name $ModelName
            } else {
                Invoke-ModelDownload -Url $ModelUrl -Name $ModelName
            }
        }
        "Validate" { Invoke-ModelValidation -Name $ModelName }
        "Remove" { Invoke-ModelRemoval -Name $ModelName }
        "Info" { Show-ModelInfo -Name $ModelName }
        "Configure" { Export-ModelConfiguration }
    }
    
    Write-Host ""
}

Main
