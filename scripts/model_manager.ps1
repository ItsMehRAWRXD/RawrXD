# RawrXD OMEGA-1 Model Manager
# Download, verify, and manage GGUF models

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("list", "download", "verify", "delete", "info", "cleanup")]
    [string]$Action = "list",
    
    [string]$ModelUrl = "",
    [string]$ModelName = "",
    [string]$ModelsDir = "$env:LOCALAPPDATA\RawrXD\OMEGA1\models",
    [switch]$Force = $false
)

$ErrorActionPreference = 'Stop'

# Common model sources
$ModelSources = @{
    "llama-2-7b-q4_0" = "https://huggingface.co/TheBloke/Llama-2-7B-GGUF/resolve/main/llama-2-7b.Q4_0.gguf"
    "llama-2-13b-q4_0" = "https://huggingface.co/TheBloke/Llama-2-13B-GGUF/resolve/main/llama-2-13b.Q4_0.gguf"
    "mistral-7b-q4_0" = "https://huggingface.co/TheBloke/Mistral-7B-v0.1-GGUF/resolve/main/mistral-7b-v0.1.Q4_0.gguf"
    "phi-2-q4_0" = "https://huggingface.co/TheBloke/phi-2-GGUF/resolve/main/phi-2.Q4_0.gguf"
    "codellama-7b-q4_0" = "https://huggingface.co/TheBloke/CodeLlama-7B-GGUF/resolve/main/codellama-7b.Q4_0.gguf"
}

function Write-Header {
    param($Text)
    Write-Host "`n═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
}

function Write-Status {
    param($Text, $Status)
    $color = switch ($Status) {
        "OK" { "Green" }
        "WARN" { "Yellow" }
        "FAIL" { "Red" }
        "INFO" { "White" }
        default { "Gray" }
    }
    Write-Host "  [$Status] $Text" -ForegroundColor $color
}

function Initialize-ModelsDirectory {
    if (!(Test-Path $ModelsDir)) {
        New-Item -ItemType Directory -Force -Path $ModelsDir | Out-Null
        Write-Status "Created models directory: $ModelsDir" "OK"
    }
}

function Get-ModelInfo {
    param($Path)
    
    $info = @{}
    $file = Get-Item $Path -ErrorAction SilentlyContinue
    
    if ($file) {
        $info.Name = $file.Name
        $info.Size = $file.Length
        $info.SizeGB = [math]::Round($file.Length / 1GB, 2)
        $info.Created = $file.CreationTime
        $info.Modified = $file.LastWriteTime
        
        # Try to extract GGUF metadata
        try {
            $header = [System.IO.File]::ReadAllBytes($Path)[0..3]
            $magic = [System.Text.Encoding]::ASCII.GetString($header)
            $info.Format = if ($magic -eq "GGUF") { "GGUF" } else { "Unknown" }
        } catch {
            $info.Format = "Unknown"
        }
        
        # Calculate hash for verification
        try {
            $hash = Get-FileHash $Path -Algorithm SHA256 -ErrorAction SilentlyContinue
            $info.Hash = $hash.Hash.Substring(0, 16) + "..."
        } catch {
            $info.Hash = "N/A"
        }
    }
    
    return $info
}

function Show-ModelList {
    Write-Header "Installed Models"
    
    Initialize-ModelsDirectory
    
    $models = Get-ChildItem $ModelsDir -Filter "*.gguf" -ErrorAction SilentlyContinue
    
    if ($models.Count -eq 0) {
        Write-Status "No models found in $ModelsDir" "WARN"
        Write-Host "`n  Use 'download' action to install models." -ForegroundColor Gray
        return
    }
    
    Write-Status "Found $($models.Count) model(s)" "OK"
    Write-Host ""
    
    $index = 1
    foreach ($model in $models) {
        $info = Get-ModelInfo $model.FullName
        
        Write-Host "  [$index] $($info.Name)" -ForegroundColor White
        Write-Host "      Size: $($info.SizeGB) GB" -ForegroundColor Gray
        Write-Host "      Format: $($info.Format)" -ForegroundColor Gray
        Write-Host "      Modified: $($info.Modified)" -ForegroundColor Gray
        Write-Host "      Hash: $($info.Hash)" -ForegroundColor Gray
        Write-Host ""
        
        $index++
    }
}

function Show-AvailableModels {
    Write-Header "Available Models"
    
    Write-Status "Pre-configured model sources:" "INFO"
    Write-Host ""
    
    foreach ($source in $ModelSources.GetEnumerator()) {
        Write-Host "  - $($source.Key)" -ForegroundColor White
        Write-Host "    URL: $($source.Value)" -ForegroundColor Gray
        Write-Host ""
    }
    
    Write-Host "  Use: model_manager.ps1 -Action download -ModelName <name>" -ForegroundColor Yellow
}

function Download-Model {
    param($Name, $Url)
    
    Write-Header "Downloading Model"
    
    Initialize-ModelsDirectory
    
    # Resolve model URL
    if ([string]::IsNullOrEmpty($Url) -and $ModelSources.ContainsKey($Name)) {
        $Url = $ModelSources[$Name]
    }
    
    if ([string]::IsNullOrEmpty($Url)) {
        Write-Status "No URL specified for model: $Name" "FAIL"
        Write-Host "`n  Available models:" -ForegroundColor Yellow
        $ModelSources.Keys | ForEach-Object { Write-Host "    - $_" -ForegroundColor Gray }
        return
    }
    
    $outputFile = if ($Name) { "$ModelsDir\$Name.gguf" } else { "$ModelsDir\downloaded_model.gguf" }
    
    if (Test-Path $outputFile) {
        if (!$Force) {
            Write-Status "Model already exists: $outputFile" "WARN"
            Write-Host "  Use -Force to overwrite" -ForegroundColor Gray
            return
        }
        Write-Status "Overwriting existing model" "WARN"
    }
    
    Write-Status "Downloading from: $Url" "INFO"
    Write-Status "Saving to: $outputFile" "INFO"
    
    try {
        $progressPreference = 'Continue'
        Invoke-WebRequest -Uri $Url -OutFile $outputFile -UseBasicParsing
        
        $size = [math]::Round((Get-Item $outputFile).Length / 1MB, 2)
        Write-Status "Download complete: $size MB" "OK"
        
        # Verify the download
        $info = Get-ModelInfo $outputFile
        if ($info.Format -eq "GGUF") {
            Write-Status "Model format verified: GGUF" "OK"
        } else {
            Write-Status "Model format warning: $($info.Format)" "WARN"
        }
        
    } catch {
        Write-Status "Download failed: $_" "FAIL"
        if (Test-Path $outputFile) {
            Remove-Item $outputFile -Force
        }
    }
}

function Verify-Models {
    Write-Header "Verifying Models"
    
    Initialize-ModelsDirectory
    
    $models = Get-ChildItem $ModelsDir -Filter "*.gguf" -ErrorAction SilentlyContinue
    
    if ($models.Count -eq 0) {
        Write-Status "No models to verify" "WARN"
        return
    }
    
    $verified = 0
    $failed = 0
    
    foreach ($model in $models) {
        Write-Host "  Verifying: $($model.Name)..." -NoNewline -ForegroundColor Gray
        
        try {
            $info = Get-ModelInfo $model.FullName
            
            if ($info.Format -eq "GGUF") {
                Write-Host " OK" -ForegroundColor Green
                $verified++
            } else {
                Write-Host " INVALID FORMAT" -ForegroundColor Red
                $failed++
            }
        } catch {
            Write-Host " ERROR" -ForegroundColor Red
            $failed++
        }
    }
    
    Write-Host ""
    Write-Status "Verified: $verified, Failed: $failed" $(if($failed -eq 0){"OK"}else{"WARN"})
}

function Remove-Model {
    param($Name)
    
    Write-Header "Removing Model"
    
    $modelPath = Join-Path $ModelsDir "$Name.gguf"
    
    if (!(Test-Path $modelPath)) {
        # Try to find by partial match
        $matches = Get-ChildItem $ModelsDir -Filter "*$Name*.gguf" -ErrorAction SilentlyContinue
        if ($matches.Count -eq 1) {
            $modelPath = $matches[0].FullName
        } elseif ($matches.Count -gt 1) {
            Write-Status "Multiple matches found:" "WARN"
            $matches | ForEach-Object { Write-Host "    - $($_.Name)" -ForegroundColor Gray }
            return
        } else {
            Write-Status "Model not found: $Name" "FAIL"
            return
        }
    }
    
    $file = Get-Item $modelPath
    $size = [math]::Round($file.Length / 1MB, 2)
    
    Write-Status "Found: $($file.Name) ($size MB)" "INFO"
    
    if (!$Force) {
        $confirm = Read-Host "  Are you sure you want to delete this model? (y/N)"
        if ($confirm -ne 'y') {
            Write-Status "Deletion cancelled" "INFO"
            return
        }
    }
    
    try {
        Remove-Item $modelPath -Force
        Write-Status "Model deleted successfully" "OK"
    } catch {
        Write-Status "Failed to delete model: $_" "FAIL"
    }
}

function Show-ModelInfo {
    param($Name)
    
    Write-Header "Model Information"
    
    $modelPath = Join-Path $ModelsDir "$Name.gguf"
    
    if (!(Test-Path $modelPath)) {
        # Try partial match
        $matches = Get-ChildItem $ModelsDir -Filter "*$Name*.gguf" -ErrorAction SilentlyContinue
        if ($matches.Count -eq 1) {
            $modelPath = $matches[0].FullName
        } else {
            Write-Status "Model not found: $Name" "FAIL"
            return
        }
    }
    
    $info = Get-ModelInfo $modelPath
    
    Write-Status "Name: $($info.Name)" "INFO"
    Write-Status "Size: $($info.SizeGB) GB ($($info.Size) bytes)" "INFO"
    Write-Status "Format: $($info.Format)" "INFO"
    Write-Status "Created: $($info.Created)" "INFO"
    Write-Status "Modified: $($info.Modified)" "INFO"
    Write-Status "SHA256: $($info.Hash)" "INFO"
    Write-Status "Path: $modelPath" "INFO"
}

function Clear-OldModels {
    Write-Header "Cleaning Up Old Models"
    
    Initialize-ModelsDirectory
    
    $cutoffDate = (Get-Date).AddDays(-30)
    $oldModels = Get-ChildItem $ModelsDir -Filter "*.gguf" | Where-Object { $_.LastWriteTime -lt $cutoffDate }
    
    if ($oldModels.Count -eq 0) {
        Write-Status "No old models to clean up" "OK"
        return
    }
    
    $totalSize = ($oldModels | Measure-Object -Property Length -Sum).Sum / 1MB
    
    Write-Status "Found $($oldModels.Count) old model(s)" "WARN"
    Write-Status "Total size: $([math]::Round($totalSize, 2)) MB" "INFO"
    
    foreach ($model in $oldModels) {
        Write-Host "  - $($model.Name) (last modified: $($model.LastWriteTime))" -ForegroundColor Gray
    }
    
    if (!$Force) {
        $confirm = Read-Host "`n  Delete these models? (y/N)"
        if ($confirm -ne 'y') {
            Write-Status "Cleanup cancelled" "INFO"
            return
        }
    }
    
    $deleted = 0
    foreach ($model in $oldModels) {
        try {
            Remove-Item $model.FullName -Force
            $deleted++
        } catch {
            Write-Status "Failed to delete $($model.Name)" "WARN"
        }
    }
    
    Write-Status "Deleted $deleted model(s)" "OK"
}

# =============================================================================
# Main Execution
# =============================================================================
Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     RawrXD OMEGA-1 Model Manager                                               ║" -ForegroundColor Cyan
Write-Host "║     Action: $Action" -NoNewline -ForegroundColor Cyan
Write-Host "$(' ' * (63 - $Action.Length))║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

switch ($Action) {
    "list" { Show-ModelList }
    "download" { 
        if ($ModelSources.ContainsKey($ModelName)) {
            Download-Model -Name $ModelName
        } elseif ($ModelUrl) {
            Download-Model -Name $ModelName -Url $ModelUrl
        } else {
            Show-AvailableModels
        }
    }
    "verify" { Verify-Models }
    "delete" { 
        if ([string]::IsNullOrEmpty($ModelName)) {
            Write-Status "Model name required for delete action" "FAIL"
            Show-ModelList
        } else {
            Remove-Model -Name $ModelName
        }
    }
    "info" { 
        if ([string]::IsNullOrEmpty($ModelName)) {
            Write-Status "Model name required for info action" "FAIL"
            Show-ModelList
        } else {
            Show-ModelInfo -Name $ModelName
        }
    }
    "cleanup" { Clear-OldModels }
}

Write-Host "`nModel Manager complete!`n" -ForegroundColor Cyan
