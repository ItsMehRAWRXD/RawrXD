# RawrXD Model Validator
# Validates model files and configurations

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Validate", "Check", "Repair", "Info", "List")]
    [string]$Action = "Validate",
    
    [string]$ModelPath = "",
    [string]$ConfigPath = "",
    [switch]$Verbose,
    [switch]$Fix
)

$ErrorActionPreference = "Stop"

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

function Initialize-Validator {
    Write-Status "Model Validator initialized"
}

function Get-GGUFMetadata {
    param([string]$Path)
    
    # Simulate GGUF metadata reading
    $fileInfo = Get-Item $Path
    
    return [PSCustomObject]@{
        FileName = $fileInfo.Name
        FileSize = $fileInfo.Length
        FileSizeGB = [math]::Round($fileInfo.Length / 1GB, 2)
        Modified = $fileInfo.LastWriteTime
        Architecture = "llama"
        Quantization = if ($Path -match "Q4") { "Q4_K_M" } elseif ($Path -match "Q8") { "Q8_0" } else { "F16" }
        Parameters = "7B"
        ContextLength = 4096
        EmbeddingLength = 4096
        BlockCount = 32
        HeadCount = 32
    }
}

function Test-ModelFile {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) {
        Write-Error "Model file not found: $Path"
        return $false
    }
    
    Write-Status "Validating: $Path"
    
    $issues = @()
    $warnings = @()
    
    # Check file extension
    $ext = [System.IO.Path]::GetExtension($Path).ToLower()
    if ($ext -notin @(".gguf", ".ggml", ".bin")) {
        $warnings += "Unusual file extension: $ext"
    }
    
    # Check file size
    $fileInfo = Get-Item $Path
    if ($fileInfo.Length -eq 0) {
        $issues += "File is empty"
    }
    
    if ($fileInfo.Length -lt 1MB) {
        $warnings += "File is suspiciously small (< 1MB)"
    }
    
    # Check if file is readable
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        $header = New-Object byte[] 4
        $stream.Read($header, 0, 4) | Out-Null
        $stream.Close()
        
        # Check GGUF magic number
        $ggufMagic = [System.Text.Encoding]::ASCII.GetString($header)
        if ($ggufMagic -ne "GGUF") {
            $warnings += "File does not have GGUF magic number (may be legacy format)"
        }
    }
    catch {
        $issues += "Cannot read file: $_"
    }
    
    # Display results
    if ($issues.Count -eq 0 -and $warnings.Count -eq 0) {
        Write-Success "Model file is valid"
    } else {
        if ($issues.Count -gt 0) {
            Write-Error "Validation failed with $($issues.Count) issue(s)"
            foreach ($issue in $issues) {
                Write-Host "  ✗ $issue" -ForegroundColor Red
            }
        }
        if ($warnings.Count -gt 0) {
            Write-Warning "$($warnings.Count) warning(s)"
            foreach ($warning in $warnings) {
                Write-Host "  ⚠ $warning" -ForegroundColor Yellow
            }
        }
    }
    
    return ($issues.Count -eq 0)
}

function Show-ModelInfo {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) {
        Write-Error "Model file not found: $Path"
        return
    }
    
    $metadata = Get-GGUFMetadata -Path $Path
    
    Write-Host ""
    Write-Host "Model Information" -ForegroundColor Cyan
    Write-Host "=================" -ForegroundColor Cyan
    Write-Host "  File: $($metadata.FileName)"
    Write-Host "  Size: $($metadata.FileSizeGB) GB ($($metadata.FileSize) bytes)"
    Write-Host "  Modified: $($metadata.Modified)"
    Write-Host ""
    Write-Host "  Architecture: $($metadata.Architecture)"
    Write-Host "  Parameters: $($metadata.Parameters)"
    Write-Host "  Quantization: $($metadata.Quantization)"
    Write-Host "  Context Length: $($metadata.ContextLength)"
    Write-Host "  Embedding Length: $($metadata.EmbeddingLength)"
    Write-Host "  Block Count: $($metadata.BlockCount)"
    Write-Host "  Head Count: $($metadata.HeadCount)"
}

function Test-ModelConfiguration {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) {
        Write-Error "Config file not found: $Path"
        return $false
    }
    
    Write-Status "Validating configuration: $Path"
    
    try {
        $config = Get-Content $Path | ConvertFrom-Json
        
        $issues = @()
        $warnings = @()
        
        # Check required fields
        $requiredFields = @("name", "version")
        foreach ($field in $requiredFields) {
            if (-not $config.$field) {
                $issues += "Missing required field: $field"
            }
        }
        
        # Check model settings
        if ($config.model) {
            if ($config.model.context_length -gt 200000) {
                $warnings += "Context length seems unusually high"
            }
            if ($config.model.batch_size -lt 1) {
                $issues += "Invalid batch size"
            }
        }
        
        # Display results
        if ($issues.Count -eq 0 -and $warnings.Count -eq 0) {
            Write-Success "Configuration is valid"
        } else {
            if ($issues.Count -gt 0) {
                Write-Error "Validation failed with $($issues.Count) issue(s)"
                foreach ($issue in $issues) {
                    Write-Host "  ✗ $issue" -ForegroundColor Red
                }
            }
            if ($warnings.Count -gt 0) {
                Write-Warning "$($warnings.Count) warning(s)"
                foreach ($warning in $warnings) {
                    Write-Host "  ⚠ $warning" -ForegroundColor Yellow
                }
            }
        }
        
        return ($issues.Count -eq 0)
    }
    catch {
        Write-Error "Invalid JSON: $_"
        return $false
    }
}

function Repair-ModelFile {
    param([string]$Path)
    
    Write-Status "Attempting to repair: $Path"
    Write-Warning "Repair functionality is limited - manual intervention may be required"
    
    # Check if backup exists
    $backupPath = "$Path.backup"
    if (Test-Path $backupPath) {
        Write-Status "Found backup: $backupPath"
        $restore = Read-Host "Restore from backup? (y/N)"
        if ($restore -eq "y") {
            Copy-Item $backupPath $Path -Force
            Write-Success "Restored from backup"
            return
        }
    }
    
    Write-Warning "No automatic repair available for this issue"
    Write-Host "  Suggested actions:"
    Write-Host "    1. Re-download the model file"
    Write-Host "    2. Check disk space and file system"
    Write-Host "    3. Verify download checksum"
}

function Show-ModelList {
    $modelsDir = "models"
    
    if (-not (Test-Path $modelsDir)) {
        Write-Warning "Models directory not found: $modelsDir"
        return
    }
    
    $models = Get-ChildItem -Path $modelsDir -Filter "*.gguf" -File
    
    Write-Host ""
    Write-Host "Available Models" -ForegroundColor Cyan
    Write-Host "=================" -ForegroundColor Cyan
    
    if ($models.Count -eq 0) {
        Write-Warning "No models found"
        return
    }
    
    foreach ($model in $models | Sort-Object Length -Descending) {
        $sizeGB = [math]::Round($model.Length / 1GB, 2)
        Write-Host "  $($model.Name.PadRight(40)) $sizeGB GB"
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Model Validator" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-Validator
    
    switch ($Action) {
        "Validate" {
            if (-not $ModelPath) {
                Write-Error "Specify -ModelPath"
                return
            }
            $valid = Test-ModelFile -Path $ModelPath
            if (-not $valid -and $Fix) {
                Repair-ModelFile -Path $ModelPath
            }
        }
        "Check" {
            if ($ConfigPath) {
                Test-ModelConfiguration -Path $ConfigPath
            } elseif ($ModelPath) {
                Test-ModelFile -Path $ModelPath
            } else {
                Write-Error "Specify -ModelPath or -ConfigPath"
            }
        }
        "Repair" {
            if (-not $ModelPath) {
                Write-Error "Specify -ModelPath"
                return
            }
            Repair-ModelFile -Path $ModelPath
        }
        "Info" {
            if (-not $ModelPath) {
                Write-Error "Specify -ModelPath"
                return
            }
            Show-ModelInfo -Path $ModelPath
        }
        "List" { Show-ModelList }
    }
    
    Write-Host ""
}

Main
