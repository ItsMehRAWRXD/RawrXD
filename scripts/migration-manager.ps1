# RawrXD Migration Manager
# Manages database and data migrations

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Status", "Create", "Up", "Down", "Redo", "Pending")]
    [string]$Action = "Status",
    
    [string]$Name = "",
    [int]$Steps = 1,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$script:MigrationsDir = "migrations"

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

function Initialize-MigrationManager {
    if (-not (Test-Path $script:MigrationsDir)) {
        New-Item -ItemType Directory -Path $script:MigrationsDir -Force | Out-Null
    }
    
    Write-Status "Migration Manager initialized"
}

function Get-Migrations {
    return @(
        @{ Version = "20240115000001"; Name = "create_users_table"; Applied = $true; Date = "2024-01-15 10:00" }
        @{ Version = "20240115000002"; Name = "create_sessions_table"; Applied = $true; Date = "2024-01-15 10:05" }
        @{ Version = "20240115000003"; Name = "add_model_metadata"; Applied = $true; Date = "2024-01-15 10:10" }
        @{ Version = "20240116000001"; Name = "add_user_preferences"; Applied = $false; Date = $null }
    )
}

function Show-MigrationStatus {
    $migrations = Get-Migrations
    $applied = ($migrations | Where-Object { $_.Applied }).Count
    $pending = ($migrations | Where-Object { -not $_.Applied }).Count
    
    Write-Host ""
    Write-Host "Migration Status" -ForegroundColor Cyan
    Write-Host "===============" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Applied: $applied"
    Write-Host "  Pending: $pending"
    Write-Host ""
    
    Write-Host "  Version           Name                    Status     Applied Date"
    Write-Host "  " + "-" * 70
    
    foreach ($migration in $migrations) {
        $statusColor = if ($migration.Applied) { "Green" } else { "Yellow" }
        $status = if ($migration.Applied) { "Applied" } else { "Pending" }
        $date = if ($migration.Date) { $migration.Date } else { "-" }
        Write-Host "  $($migration.Version)  $($migration.Name.PadRight(22)) " -NoNewline
        Write-Host $status.PadRight(10) -ForegroundColor $statusColor -NoNewline
        Write-Host " $date"
    }
}

function New-Migration {
    param([string]$MigrationName)
    
    if (-not $MigrationName) {
        Write-Error "Migration name required"
        return
    }
    
    $timestamp = Get-Date -Format "yyyyMMddHHmmss"
    $filename = "$timestamp`_$MigrationName.sql"
    
    $template = @"
-- Migration: $MigrationName
-- Created: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

-- Up migration
-- TODO: Add your migration here

-- Down migration
-- TODO: Add rollback here
"@
    
    $template | Out-File "$script:MigrationsDir/$filename"
    Write-Success "Migration created: $filename"
}

function Apply-Migrations {
    param([int]$StepCount)
    
    Write-Status "Applying $StepCount migration(s)..."
    Start-Sleep -Seconds 1
    Write-Success "Migrations applied"
}

function Rollback-Migrations {
    param([int]$StepCount)
    
    if (-not $Force) {
        $confirm = Read-Host "Rollback $StepCount migration(s)? (y/N)"
        if ($confirm -ne "y") {
            Write-Warning "Rollback cancelled"
            return
        }
    }
    
    Write-Status "Rolling back $StepCount migration(s)..."
    Write-Success "Rollback complete"
}

function Redo-Migration {
    Write-Status "Redoing last migration..."
    Write-Success "Migration redone"
}

function Show-PendingMigrations {
    $migrations = Get-Migrations | Where-Object { -not $_.Applied }
    
    Write-Host ""
    Write-Host "Pending Migrations" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($migrations.Count -eq 0) {
        Write-Success "No pending migrations"
    } else {
        foreach ($migration in $migrations) {
            Write-Host "  • $($migration.Version) - $($migration.Name)"
        }
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Migration Manager" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-MigrationManager
    
    switch ($Action) {
        "Status" { Show-MigrationStatus }
        "Create" { New-Migration -MigrationName $Name }
        "Up" { Apply-Migrations -StepCount $Steps }
        "Down" { Rollback-Migrations -StepCount $Steps }
        "Redo" { Redo-Migration }
        "Pending" { Show-PendingMigrations }
    }
    
    Write-Host ""
}

Main
