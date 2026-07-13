# RawrXD Database Manager
# Manages database connections, migrations, and operations

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Connect", "Query", "Migrate", "Backup", "Restore", "Status", "Optimize")]
    [string]$Action = "Status",
    
    [ValidateSet("SQLite", "PostgreSQL", "MySQL", "SQLServer")]
    [string]$DatabaseType = "SQLite",
    
    [string]$ConnectionString = "",
    [string]$DatabasePath = "data/rawrxd.db",
    [string]$Query = "",
    [string]$MigrationPath = "migrations",
    [string]$BackupPath = "backups",
    [switch]$DryRun,
    [switch]$Force
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

function Initialize-DatabaseManager {
    Write-Status "Database Manager initialized"
    Write-Status "Database Type: $DatabaseType"
    Write-Status "Action: $Action"
    
    # Ensure directories exist
    $dbDir = Split-Path $DatabasePath -Parent
    if ($dbDir -and -not (Test-Path $dbDir)) {
        New-Item -ItemType Directory -Path $dbDir -Force | Out-Null
    }
}

function Get-ConnectionString {
    if ($ConnectionString) {
        return $ConnectionString
    }
    
    switch ($DatabaseType) {
        "SQLite" { return "Data Source=$DatabasePath;Version=3;" }
        "PostgreSQL" { return $env:RAWRXD_POSTGRESQL_CONN }
        "MySQL" { return $env:RAWRXD_MYSQL_CONN }
        "SQLServer" { return $env:RAWRXD_SQLSERVER_CONN }
    }
    
    return ""
}

function Test-DatabaseConnection {
    Write-Status "Testing database connection..."
    
    $connString = Get-ConnectionString
    
    try {
        switch ($DatabaseType) {
            "SQLite" {
                if (-not (Test-Path $DatabasePath)) {
                    Write-Warning "Database file does not exist, will be created"
                    return $true
                }
                
                # Test SQLite connection
                $connection = New-Object System.Data.SQLite.SQLiteConnection($connString)
                $connection.Open()
                $connection.Close()
            }
            default {
                Write-Warning "Connection test for $DatabaseType not implemented"
                return $true
            }
        }
        
        Write-Success "Database connection successful"
        return $true
    }
    catch {
        Write-Error "Database connection failed: $_"
        return $false
    }
}

function Invoke-DatabaseQuery {
    if (-not $Query) {
        Write-Error "Query parameter required for Query action"
        return
    }
    
    Write-Status "Executing query..."
    
    if ($DryRun) {
        Write-Status "Would execute: $Query"
        return
    }
    
    try {
        switch ($DatabaseType) {
            "SQLite" {
                $connString = Get-ConnectionString
                $connection = New-Object System.Data.SQLite.SQLiteConnection($connString)
                $connection.Open()
                
                $command = $connection.CreateCommand()
                $command.CommandText = $Query
                
                if ($Query -match '^\s*SELECT') {
                    $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
                    $dataset = New-Object System.Data.DataSet
                    $adapter.Fill($dataset) | Out-Null
                    
                    $dataset.Tables[0] | Format-Table -AutoSize
                } else {
                    $rowsAffected = $command.ExecuteNonQuery()
                    Write-Success "Query executed. Rows affected: $rowsAffected"
                }
                
                $connection.Close()
            }
            default {
                Write-Error "Query execution for $DatabaseType not implemented"
            }
        }
    }
    catch {
        Write-Error "Query execution failed: $_"
    }
}

function Invoke-DatabaseMigration {
    Write-Status "Running database migrations..."
    
    if (-not (Test-Path $MigrationPath)) {
        Write-Warning "Migration path does not exist: $MigrationPath"
        return
    }
    
    $migrations = Get-ChildItem -Path $MigrationPath -Filter "*.sql" | Sort-Object Name
    
    if ($migrations.Count -eq 0) {
        Write-Warning "No migration files found"
        return
    }
    
    Write-Status "Found $($migrations.Count) migration files"
    
    foreach ($migration in $migrations) {
        Write-Status "Applying migration: $($migration.Name)"
        
        if ($DryRun) {
            Write-Status "Would apply: $($migration.FullName)"
            continue
        }
        
        try {
            $sql = Get-Content $migration.FullName -Raw
            Invoke-DatabaseQuery -Query $sql
            Write-Success "Applied: $($migration.Name)"
        }
        catch {
            Write-Error "Failed to apply $($migration.Name): $_"
            if (-not $Force) {
                return
            }
        }
    }
}

function Backup-Database {
    Write-Status "Creating database backup..."
    
    if (-not (Test-Path $DatabasePath)) {
        Write-Error "Database file not found: $DatabasePath"
        return
    }
    
    if (-not (Test-Path $BackupPath)) {
        New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backupFile = "$BackupPath/rawrxd-backup-$timestamp.db"
    
    if ($DryRun) {
        Write-Status "Would backup to: $backupFile"
        return
    }
    
    try {
        Copy-Item -Path $DatabasePath -Destination $backupFile
        
        # Compress backup
        $compressedFile = "$backupFile.zip"
        Compress-Archive -Path $backupFile -DestinationPath $compressedFile -Force
        Remove-Item $backupFile
        
        Write-Success "Database backed up to: $compressedFile"
    }
    catch {
        Write-Error "Backup failed: $_"
    }
}

function Restore-Database {
    param([string]$BackupFile)
    
    if (-not $BackupFile) {
        # List available backups
        $backups = Get-ChildItem -Path $BackupPath -Filter "*.zip" | Sort-Object LastWriteTime -Descending
        
        if ($backups.Count -eq 0) {
            Write-Error "No backups found in $BackupPath"
            return
        }
        
        Write-Host "Available backups:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $backups.Count; $i++) {
            Write-Host "  [$i] $($backups[$i].Name)"
        }
        
        $selection = Read-Host "Select backup to restore (number)"
        $BackupFile = $backups[$selection].FullName
    }
    
    if (-not (Test-Path $BackupFile)) {
        Write-Error "Backup file not found: $BackupFile"
        return
    }
    
    if (-not $Force) {
        $confirm = Read-Host "This will overwrite the current database. Continue? (yes/no)"
        if ($confirm -ne "yes") {
            Write-Status "Restore cancelled"
            return
        }
    }
    
    Write-Status "Restoring from: $BackupFile"
    
    try {
        # Extract backup
        $tempPath = "$env:TEMP/rawrxd-restore-$(Get-Random)"
        Expand-Archive -Path $BackupFile -DestinationPath $tempPath -Force
        
        # Find database file in extracted archive
        $dbFile = Get-ChildItem -Path $tempPath -Filter "*.db" | Select-Object -First 1
        
        if (-not $dbFile) {
            Write-Error "No database file found in backup"
            return
        }
        
        # Backup current database
        if (Test-Path $DatabasePath) {
            $currentBackup = "$DatabasePath.bak.$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            Copy-Item -Path $DatabasePath -Destination $currentBackup
            Write-Status "Current database backed up to: $currentBackup"
        }
        
        # Restore
        Copy-Item -Path $dbFile.FullName -Destination $DatabasePath -Force
        
        # Cleanup
        Remove-Item -Path $tempPath -Recurse -Force
        
        Write-Success "Database restored successfully"
    }
    catch {
        Write-Error "Restore failed: $_"
    }
}

function Get-DatabaseStatus {
    Write-Status "Database Status" -ForegroundColor Cyan
    Write-Status "==============" -ForegroundColor Cyan
    
    Write-Host "Database Type: $DatabaseType"
    Write-Host "Database Path: $DatabasePath"
    
    if (Test-Path $DatabasePath) {
        $fileInfo = Get-Item $DatabasePath
        Write-Host "File Size: $([math]::Round($fileInfo.Length / 1MB, 2)) MB"
        Write-Host "Created: $($fileInfo.CreationTime)"
        Write-Host "Modified: $($fileInfo.LastWriteTime)"
        
        # Get table count
        try {
            $query = "SELECT name FROM sqlite_master WHERE type='table'"
            Invoke-DatabaseQuery -Query $query
        }
        catch {
            Write-Warning "Could not retrieve table information"
        }
    } else {
        Write-Warning "Database file does not exist"
    }
}

function Optimize-Database {
    Write-Status "Optimizing database..."
    
    if ($DryRun) {
        Write-Status "Would optimize database"
        return
    }
    
    try {
        switch ($DatabaseType) {
            "SQLite" {
                Invoke-DatabaseQuery -Query "VACUUM;"
                Invoke-DatabaseQuery -Query "ANALYZE;"
                Write-Success "Database optimized"
            }
            default {
                Write-Warning "Optimization for $DatabaseType not implemented"
            }
        }
    }
    catch {
        Write-Error "Optimization failed: $_"
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Database Manager" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-DatabaseManager
    
    switch ($Action) {
        "Connect" { Test-DatabaseConnection }
        "Query" { Invoke-DatabaseQuery }
        "Migrate" { Invoke-DatabaseMigration }
        "Backup" { Backup-Database }
        "Restore" { Restore-Database }
        "Status" { Get-DatabaseStatus }
        "Optimize" { Optimize-Database }
    }
    
    Write-Host ""
}

Main
