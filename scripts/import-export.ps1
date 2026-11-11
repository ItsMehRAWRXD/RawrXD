# RawrXD Import/Export Manager
# Manages data import and export operations

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Export", "Import", "Convert", "Validate", "List")]
    [string]$Action = "List",
    
    [string]$Source = "",
    [string]$Destination = "",
    [ValidateSet("json", "csv", "xml", "yaml", "parquet", "gguf")]
    [string]$Format = "json",
    [string]$Filter = "*",
    [switch]$Compress,
    [switch]$Overwrite
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

function Initialize-ImportExport {
    Write-Status "Import/Export Manager initialized"
    Write-Status "Action: $Action"
    Write-Status "Format: $Format"
}

function Export-DataPackage {
    param([string]$SourcePath, [string]$DestPath, [string]$DataFormat)
    
    if (-not (Test-Path $SourcePath)) {
        Write-Error "Source not found: $SourcePath"
        return
    }
    
    Write-Status "Exporting data from: $SourcePath"
    
    $tempDir = "$env:TEMP/rawrxd-export-$(Get-Random)"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    
    try {
        # Collect data based on source type
        $data = @{}
        
        if (Test-Path "$SourcePath/config.json") {
            $data.config = Get-Content "$SourcePath/config.json" | ConvertFrom-Json
        }
        
        if (Test-Path "$SourcePath/models") {
            $data.models = Get-ChildItem "$SourcePath/models" -Filter "*.gguf" | Select-Object Name, Length, LastWriteTime
        }
        
        if (Test-Path "$SourcePath/logs") {
            $data.logs = Get-ChildItem "$SourcePath/logs" -Filter "*.log" | Select-Object Name, Length, LastWriteTime
        }
        
        # Export in specified format
        $outputFile = "$tempDir/export.$(Get-Date -Format 'yyyyMMdd-HHmmss').$DataFormat"
        
        switch ($DataFormat) {
            "json" {
                $data | ConvertTo-Json -Depth 10 | Out-File $outputFile
            }
            "csv" {
                # Flatten data for CSV
                $flatData = @()
                foreach ($key in $data.Keys) {
                    $flatData += [PSCustomObject]@{
                        Category = $key
                        Data = ($data[$key] | ConvertTo-Json -Compress)
                    }
                }
                $flatData | Export-Csv $outputFile -NoTypeInformation
            }
            "xml" {
                $data | Export-Clixml $outputFile
            }
            "yaml" {
                # Simple YAML conversion
                $yaml = ""
                foreach ($key in $data.Keys) {
                    $yaml += "$key:`n"
                    $yaml += ($data[$key] | ConvertTo-Json -Depth 3)
                    $yaml += "`n"
                }
                $yaml | Out-File $outputFile
            }
        }
        
        # Compress if requested
        if ($Compress) {
            $zipFile = "$DestPath/export-$(Get-Date -Format 'yyyyMMdd-HHmmss').zip"
            Compress-Archive -Path $outputFile -DestinationPath $zipFile
            Write-Success "Exported to: $zipFile"
        } else {
            Copy-Item $outputFile $DestPath
            Write-Success "Exported to: $DestPath"
        }
    }
    finally {
        Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Import-DataPackage {
    param([string]$SourcePath, [string]$DestPath)
    
    if (-not (Test-Path $SourcePath)) {
        Write-Error "Source not found: $SourcePath"
        return
    }
    
    Write-Status "Importing data from: $SourcePath"
    
    # Detect format
    $ext = [System.IO.Path]::GetExtension($SourcePath).ToLower()
    
    try {
        $data = $null
        
        switch ($ext) {
            ".json" {
                $data = Get-Content $SourcePath | ConvertFrom-Json
            }
            ".csv" {
                $data = Import-Csv $SourcePath
            }
            ".xml" {
                $data = Import-Clixml $SourcePath
            }
            ".zip" {
                $tempDir = "$env:TEMP/rawrxd-import-$(Get-Random)"
                Expand-Archive -Path $SourcePath -DestinationPath $tempDir
                $jsonFile = Get-ChildItem $tempDir -Filter "*.json" | Select-Object -First 1
                if ($jsonFile) {
                    $data = Get-Content $jsonFile.FullName | ConvertFrom-Json
                }
                Remove-Item $tempDir -Recurse -Force
            }
        }
        
        if ($data) {
            # Apply imported data
            if ($data.config) {
                $data.config | ConvertTo-Json -Depth 10 | Out-File "$DestPath/config.json"
            }
            
            Write-Success "Data imported successfully"
        }
    }
    catch {
        Write-Error "Import failed: $_"
    }
}

function Convert-DataFormat {
    param([string]$SourcePath, [string]$TargetFormat)
    
    if (-not (Test-Path $SourcePath)) {
        Write-Error "Source not found: $SourcePath"
        return
    }
    
    Write-Status "Converting data to: $TargetFormat"
    
    $sourceExt = [System.IO.Path]::GetExtension($SourcePath).ToLower().TrimStart('.')
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($SourcePath)
    $destPath = "$baseName.$TargetFormat"
    
    try {
        # Read source
        $data = $null
        switch ($sourceExt) {
            "json" { $data = Get-Content $SourcePath | ConvertFrom-Json }
            "csv" { $data = Import-Csv $SourcePath }
            "xml" { $data = Import-Clixml $SourcePath }
        }
        
        if (-not $data) {
            Write-Error "Could not read source file"
            return
        }
        
        # Write target
        switch ($TargetFormat) {
            "json" { $data | ConvertTo-Json -Depth 10 | Out-File $destPath }
            "csv" { $data | Export-Csv $destPath -NoTypeInformation }
            "xml" { $data | Export-Clixml $destPath }
            "yaml" { 
                $yaml = $data | ConvertTo-Json -Depth 10
                $yaml | Out-File $destPath
            }
        }
        
        Write-Success "Converted to: $destPath"
    }
    catch {
        Write-Error "Conversion failed: $_"
    }
}

function Test-DataFile {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        Write-Error "File not found: $FilePath"
        return $false
    }
    
    Write-Status "Validating: $FilePath"
    
    $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()
    $isValid = $false
    
    try {
        switch ($ext) {
            ".json" {
                $null = Get-Content $FilePath | ConvertFrom-Json
                $isValid = $true
            }
            ".csv" {
                $null = Import-Csv $FilePath
                $isValid = $true
            }
            ".xml" {
                $null = Import-Clixml $FilePath
                $isValid = $true
            }
            default {
                Write-Warning "Unknown format: $ext"
            }
        }
        
        if ($isValid) {
            Write-Success "File is valid"
        }
    }
    catch {
        Write-Error "Validation failed: $_"
    }
    
    return $isValid
}

function Show-SupportedFormats {
    Write-Host ""
    Write-Host "Supported Formats" -ForegroundColor Cyan
    Write-Host "=================" -ForegroundColor Cyan
    Write-Host "  json    - JavaScript Object Notation"
    Write-Host "  csv     - Comma Separated Values"
    Write-Host "  xml     - Extensible Markup Language"
    Write-Host "  yaml    - YAML Ain't Markup Language"
    Write-Host "  parquet - Apache Parquet (binary)"
    Write-Host "  gguf    - GGML/GGUF Model Format"
}

# Main execution
function Main {
    Write-Host "RawrXD Import/Export Manager" -ForegroundColor Cyan
    Write-Host "===========================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-ImportExport
    
    switch ($Action) {
        "Export" { Export-DataPackage -SourcePath $Source -DestPath $Destination -DataFormat $Format }
        "Import" { Import-DataPackage -SourcePath $Source -DestPath $Destination }
        "Convert" { Convert-DataFormat -SourcePath $Source -TargetFormat $Format }
        "Validate" { Test-DataFile -FilePath $Source }
        "List" { Show-SupportedFormats }
    }
    
    Write-Host ""
}

Main
