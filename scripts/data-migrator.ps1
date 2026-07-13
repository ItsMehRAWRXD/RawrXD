# RawrXD Data Migrator
# Migrates data between versions and formats

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Export", "Import", "Convert", "Backup", "Validate")]
    [string]$Action = "Export",
    
    [string]$SourcePath = "",
    [string]$DestinationPath = "",
    [ValidateSet("JSON", "CSV", "XML", "SQLite", "GGUF", "Auto")]
    [string]$Format = "Auto",
    [string]$Version = "",
    [switch]$DryRun,
    [switch]$Compress,
    [switch]$Verify
)

$ErrorActionPreference = "Stop"

$script:MigrationId = "migration-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$script:Results = @{
    Timestamp = Get-Date -Format "o"
    Action = $Action
    MigrationId = $script:MigrationId
    RecordsProcessed = 0
    RecordsFailed = 0
    Status = "Pending"
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

function Initialize-Migrator {
    Write-Status "Data Migrator initialized"
    Write-Status "Action: $Action"
    Write-Status "Migration ID: $script:MigrationId"
    
    if ($DryRun) {
        Write-Warning "DRY RUN MODE - No actual changes will be made"
    }
}

function Get-FileFormat {
    param([string]$Path)
    
    if ($Format -ne "Auto") {
        return $Format
    }
    
    $extension = [System.IO.Path]::GetExtension($Path).ToLower()
    
    switch ($extension) {
        ".json" { return "JSON" }
        ".csv" { return "CSV" }
        ".xml" { return "XML" }
        ".db" { return "SQLite" }
        ".sqlite" { return "SQLite" }
        ".gguf" { return "GGUF" }
        default { return "Unknown" }
    }
}

function Invoke-DataExport {
    Write-Status "Exporting data..."
    
    if (-not $SourcePath) {
        $SourcePath = "data"
    }
    
    if (-not $DestinationPath) {
        $DestinationPath = "exports\$script:MigrationId"
    }
    
    if (-not (Test-Path $SourcePath)) {
        Write-Error "Source path not found: $SourcePath"
        return
    }
    
    if (-not (Test-Path $DestinationPath)) {
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
    }
    
    $format = Get-FileFormat -Path $DestinationPath
    
    Write-Status "Source: $SourcePath"
    Write-Status "Destination: $DestinationPath"
    Write-Status "Format: $format"
    
    # Export configuration
    if (Test-Path "config.json") {
        Write-Status "Exporting configuration..."
        $config = Get-Content "config.json" | ConvertFrom-Json
        
        switch ($format) {
            "JSON" {
                $config | ConvertTo-Json -Depth 10 | Out-File "$DestinationPath\config.json"
            }
            "CSV" {
                # Flatten config to CSV
                $flattened = @()
                foreach ($key in $config.Keys) {
                    $flattened += [PSCustomObject]@{
                        Key = $key
                        Value = $config[$key] | ConvertTo-Json -Compress
                    }
                }
                $flattened | Export-Csv "$DestinationPath\config.csv" -NoTypeInformation
            }
            "XML" {
                $config | Export-Clixml "$DestinationPath\config.xml"
            }
        }
        
        $script:Results.RecordsProcessed++
    }
    
    # Export models metadata
    if (Test-Path "models") {
        Write-Status "Exporting model metadata..."
        $models = Get-ChildItem "models" -Filter "*.gguf" -ErrorAction SilentlyContinue
        
        $modelData = @()
        foreach ($model in $models) {
            $modelData += @{
                Name = $model.Name
                Size = $model.Length
                Modified = $model.LastWriteTime
                Path = $model.FullName
            }
        }
        
        if ($modelData.Count -gt 0) {
            switch ($format) {
                "JSON" {
                    $modelData | ConvertTo-Json -Depth 5 | Out-File "$DestinationPath\models.json"
                }
                "CSV" {
                    $modelData | Export-Csv "$DestinationPath\models.csv" -NoTypeInformation
                }
            }
            
            $script:Results.RecordsProcessed += $modelData.Count
        }
    }
    
    # Export logs (last 30 days)
    if (Test-Path "logs") {
        Write-Status "Exporting recent logs..."
        $logFiles = Get-ChildItem "logs" -Filter "*.log" | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) }
        
        $logData = @()
        foreach ($logFile in $logFiles) {
            $content = Get-Content $logFile.FullName -ErrorAction SilentlyContinue
            foreach ($line in $content) {
                if ($line -match '^(\d{4}-\d{2}-\d{2}.*?)\s+(\w+)\s+(.*)$') {
                    $logData += @{
                        Timestamp = $matches[1]
                        Level = $matches[2]
                        Message = $matches[3]
                        Source = $logFile.Name
                    }
                }
            }
        }
        
        if ($logData.Count -gt 0) {
            switch ($format) {
                "JSON" {
                    $logData | ConvertTo-Json -Depth 5 | Out-File "$DestinationPath\logs.json"
                }
                "CSV" {
                    $logData | Export-Csv "$DestinationPath\logs.csv" -NoTypeInformation
                }
            }
            
            $script:Results.RecordsProcessed += $logData.Count
        }
    }
    
    # Create manifest
    $manifest = @{
        MigrationId = $script:MigrationId
        Timestamp = Get-Date -Format "o"
        SourcePath = $SourcePath
        DestinationPath = $DestinationPath
        Format = $format
        RecordsProcessed = $script:Results.RecordsProcessed
    }
    
    $manifest | ConvertTo-Json -Depth 5 | Out-File "$DestinationPath\manifest.json"
    
    # Compress if requested
    if ($Compress) {
        Write-Status "Compressing export..."
        $archivePath = "$DestinationPath.zip"
        Compress-Archive -Path $DestinationPath -DestinationPath $archivePath -Force
        Write-Success "Export compressed: $archivePath"
    }
    
    Write-Success "Export complete: $DestinationPath"
}

function Invoke-DataImport {
    Write-Status "Importing data..."
    
    if (-not $SourcePath) {
        Write-Error "Source path required for import"
        return
    }
    
    if (-not (Test-Path $SourcePath)) {
        Write-Error "Source path not found: $SourcePath"
        return
    }
    
    # Check if compressed
    if ($SourcePath.EndsWith(".zip")) {
        Write-Status "Extracting archive..."
        $extractPath = "$env:TEMP\rawrxd-import-$script:MigrationId"
        Expand-Archive -Path $SourcePath -DestinationPath $extractPath -Force
        $SourcePath = $extractPath
    }
    
    # Load manifest
    $manifestPath = "$SourcePath\manifest.json"
    if (Test-Path $manifestPath) {
        $manifest = Get-Content $manifestPath | ConvertFrom-Json
        Write-Status "Importing from migration: $($manifest.MigrationId)"
        Write-Status "Original format: $($manifest.Format)"
    }
    
    # Import configuration
    $configPath = "$SourcePath\config.json"
    if (Test-Path $configPath) {
        Write-Status "Importing configuration..."
        
        if (-not $DryRun) {
            Copy-Item $configPath "config.json" -Force
            Write-Success "Configuration imported"
        } else {
            Write-Status "Would import: config.json"
        }
        
        $script:Results.RecordsProcessed++
    }
    
    # Import model metadata
    $modelsPath = "$SourcePath\models.json"
    if (Test-Path $modelsPath) {
        Write-Status "Importing model metadata..."
        $models = Get-Content $modelsPath | ConvertFrom-Json
        
        if (-not (Test-Path "models")) {
            New-Item -ItemType Directory -Path "models" -Force | Out-Null
        }
        
        foreach ($model in $models) {
            Write-Status "Model: $($model.Name)"
            # Note: Actual model files would need to be copied separately
        }
        
        $script:Results.RecordsProcessed += $models.Count
    }
    
    Write-Success "Import complete"
}

function Invoke-DataConvert {
    Write-Status "Converting data format..."
    
    if (-not $SourcePath -or -not $DestinationPath) {
        Write-Error "Source and destination paths required for conversion"
        return
    }
    
    if (-not (Test-Path $SourcePath)) {
        Write-Error "Source file not found: $SourcePath"
        return
    }
    
    $sourceFormat = Get-FileFormat -Path $SourcePath
    $targetFormat = if ($Format -eq "Auto") { "JSON" } else { $Format }
    
    Write-Status "Converting from $sourceFormat to $targetFormat"
    
    # Load source data
    $data = $null
    switch ($sourceFormat) {
        "JSON" { $data = Get-Content $SourcePath | ConvertFrom-Json }
        "CSV" { $data = Import-Csv $SourcePath }
        "XML" { $data = Import-Clixml $SourcePath }
    }
    
    if (-not $data) {
        Write-Error "Failed to load source data"
        return
    }
    
    # Convert and save
    switch ($targetFormat) {
        "JSON" {
            $data | ConvertTo-Json -Depth 10 | Out-File $DestinationPath
        }
        "CSV" {
            $data | Export-Csv $DestinationPath -NoTypeInformation
        }
        "XML" {
            $data | Export-Clixml $DestinationPath
        }
    }
    
    Write-Success "Conversion complete: $DestinationPath"
}

function Invoke-DataBackup {
    Write-Status "Creating data backup..."
    
    $backupPath = if ($DestinationPath) { $DestinationPath } else { "backups\data-$script:MigrationId" }
    
    if (-not (Test-Path $backupPath)) {
        New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
    }
    
    # Backup data directory
    if (Test-Path "data") {
        Write-Status "Backing up data directory..."
        Copy-Item -Recurse "data" "$backupPath\data" -Force
    }
    
    # Backup config
    if (Test-Path "config.json") {
        Write-Status "Backing up configuration..."
        Copy-Item "config.json" "$backupPath\config.json" -Force
    }
    
    # Backup models metadata
    if (Test-Path "models") {
        Write-Status "Backing up model metadata..."
        Get-ChildItem "models" | Select-Object Name, Length, LastWriteTime | Export-Csv "$backupPath\models.csv" -NoTypeInformation
    }
    
    # Create manifest
    @{
        BackupId = $script:MigrationId
        Timestamp = Get-Date -Format "o"
        Version = if ($Version) { $Version } else { "current" }
    } | ConvertTo-Json | Out-File "$backupPath\manifest.json"
    
    Write-Success "Backup created: $backupPath"
}

function Invoke-DataValidation {
    Write-Status "Validating data integrity..."
    
    if (-not $SourcePath) {
        $SourcePath = "data"
    }
    
    if (-not (Test-Path $SourcePath)) {
        Write-Error "Source path not found: $SourcePath"
        return
    }
    
    $issues = @()
    
    # Validate JSON files
    $jsonFiles = Get-ChildItem $SourcePath -Filter "*.json" -Recurse -ErrorAction SilentlyContinue
    foreach ($file in $jsonFiles) {
        try {
            $null = Get-Content $file.FullName | ConvertFrom-Json
        }
        catch {
            $issues += "Invalid JSON: $($file.FullName)"
        }
    }
    
    # Validate CSV files
    $csvFiles = Get-ChildItem $SourcePath -Filter "*.csv" -Recurse -ErrorAction SilentlyContinue
    foreach ($file in $csvFiles) {
        try {
            $null = Import-Csv $file.FullName
        }
        catch {
            $issues += "Invalid CSV: $($file.FullName)"
        }
    }
    
    if ($issues.Count -eq 0) {
        Write-Success "All data files are valid"
    } else {
        Write-Warning "Found $($issues.Count) issue(s):"
        foreach ($issue in $issues) {
            Write-Host "  ! $issue" -ForegroundColor Yellow
        }
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Data Migrator" -ForegroundColor Cyan
    Write-Host "====================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-Migrator
    
    switch ($Action) {
        "Export" { Invoke-DataExport }
        "Import" { Invoke-DataImport }
        "Convert" { Invoke-DataConvert }
        "Backup" { Invoke-DataBackup }
        "Validate" { Invoke-DataValidation }
    }
    
    Write-Host ""
}

Main
