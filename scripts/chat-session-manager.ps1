# RawrXD Chat Session Manager
# Manages chat sessions and conversations

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("List", "New", "Load", "Delete", "Export", "Import", "Archive")]
    [string]$Action = "List",
    
    [string]$SessionId = "",
    [string]$Model = "",
    [string]$ExportPath = "",
    [string]$ImportPath = "",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$script:SessionsDir = "sessions"
$script:ArchiveDir = "sessions/archive"

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

function Initialize-SessionManager {
    if (-not (Test-Path $script:SessionsDir)) {
        New-Item -ItemType Directory -Path $script:SessionsDir -Force | Out-Null
    }
    if (-not (Test-Path $script:ArchiveDir)) {
        New-Item -ItemType Directory -Path $script:ArchiveDir -Force | Out-Null
    }
    
    Write-Status "Chat Session Manager initialized"
}

function Get-SessionFiles {
    return Get-ChildItem -Path $script:SessionsDir -Filter "*.json" -File | Where-Object { $_.DirectoryName -eq (Resolve-Path $script:SessionsDir).Path }
}

function Show-SessionList {
    $sessions = Get-SessionFiles
    
    Write-Host ""
    Write-Host "Chat Sessions" -ForegroundColor Cyan
    Write-Host "=============" -ForegroundColor Cyan
    
    if ($sessions.Count -eq 0) {
        Write-Warning "No sessions found"
        return
    }
    
    Write-Host "  ID                    Model                Messages    Last Activity"
    Write-Host "  " + "-" * 70
    
    foreach ($session in $sessions | Sort-Object LastWriteTime -Descending) {
        try {
            $data = Get-Content $session.FullName | ConvertFrom-Json
            $msgCount = if ($data.messages) { $data.messages.Count } else { 0 }
            $lastActivity = $session.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
            
            Write-Host "  $($session.BaseName.PadRight(21)) $($data.model.PadRight(20)) $($msgCount.ToString().PadRight(11)) $lastActivity"
        }
        catch {
            Write-Host "  $($session.Name.PadRight(21)) [Error loading]" -ForegroundColor Red
        }
    }
}

function New-ChatSession {
    param([string]$Id, [string]$ModelName)
    
    if (-not $Id) {
        $Id = "session-$(Get-Date -Format 'yyyyMMdd-HHmmss')-$(Get-Random -Minimum 1000 -Maximum 9999)"
    }
    
    if (-not $ModelName) {
        $ModelName = "default"
    }
    
    $sessionFile = "$script:SessionsDir/$Id.json"
    
    if (Test-Path $sessionFile) {
        Write-Error "Session already exists: $Id"
        return
    }
    
    $session = @{
        id = $Id
        model = $ModelName
        created = Get-Date -Format "o"
        messages = @()
        metadata = @{
            temperature = 0.7
            max_tokens = 2048
            context_length = 4096
        }
    }
    
    $session | ConvertTo-Json -Depth 5 | Out-File $sessionFile
    Write-Success "Created new session: $Id"
    Write-Host "  Model: $ModelName"
    Write-Host "  File: $sessionFile"
}

function Get-SessionData {
    param([string]$Id)
    
    $sessionFile = "$script:SessionsDir/$Id.json"
    
    if (-not (Test-Path $sessionFile)) {
        Write-Error "Session not found: $Id"
        return $null
    }
    
    return Get-Content $sessionFile | ConvertFrom-Json
}

function Show-SessionDetails {
    param([string]$Id)
    
    $session = Get-SessionData -Id $Id
    if (-not $session) { return }
    
    Write-Host ""
    Write-Host "Session: $Id" -ForegroundColor Cyan
    Write-Host "========" + ("=" * $Id.Length) -ForegroundColor Cyan
    Write-Host "  Model: $($session.model)"
    Write-Host "  Created: $($session.created)"
    Write-Host "  Messages: $($session.messages.Count)"
    Write-Host ""
    
    if ($session.messages.Count -gt 0) {
        Write-Host "Conversation" -ForegroundColor Yellow
        foreach ($msg in $session.messages) {
            $roleColor = switch ($msg.role) {
                "user" { "Green" }
                "assistant" { "Cyan" }
                "system" { "Magenta" }
                default { "White" }
            }
            Write-Host "  [$($msg.role)]" -ForegroundColor $roleColor -NoNewline
            $content = $msg.content
            if ($content.Length -gt 80) {
                $content = $content.Substring(0, 77) + "..."
            }
            Write-Host ": $content"
        }
    }
}

function Remove-SessionFile {
    param([string]$Id)
    
    $sessionFile = "$script:SessionsDir/$Id.json"
    
    if (-not (Test-Path $sessionFile)) {
        Write-Error "Session not found: $Id"
        return
    }
    
    if (-not $Force) {
        $confirm = Read-Host "Delete session '$Id'? (y/N)"
        if ($confirm -ne "y") {
            Write-Warning "Deletion cancelled"
            return
        }
    }
    
    Remove-Item $sessionFile
    Write-Success "Deleted session: $Id"
}

function Export-SessionData {
    param([string]$Id, [string]$Path)
    
    $session = Get-SessionData -Id $Id
    if (-not $session) { return }
    
    if (-not $Path) {
        $Path = "$Id-export-$(Get-Date -Format 'yyyyMMdd').json"
    }
    
    $export = @{
        export_date = Get-Date -Format "o"
        session = $session
    }
    
    $export | ConvertTo-Json -Depth 10 | Out-File $Path
    Write-Success "Session exported to: $Path"
}

function Import-SessionData {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) {
        Write-Error "File not found: $Path"
        return
    }
    
    try {
        $import = Get-Content $Path | ConvertFrom-Json
        $session = $import.session
        
        $newId = "$($session.id)-imported-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        $sessionFile = "$script:SessionsDir/$newId.json"
        
        $session.id = $newId
        $session | ConvertTo-Json -Depth 10 | Out-File $sessionFile
        
        Write-Success "Session imported: $newId"
    }
    catch {
        Write-Error "Import failed: $_"
    }
}

function Archive-OldSessions {
    Write-Status "Archiving old sessions..."
    
    $cutoffDate = (Get-Date).AddDays(-30)
    $sessions = Get-SessionFiles | Where-Object { $_.LastWriteTime -lt $cutoffDate }
    
    $archived = 0
    foreach ($session in $sessions) {
        $dest = Join-Path $script:ArchiveDir $session.Name
        Move-Item $session.FullName $dest
        $archived++
    }
    
    Write-Success "Archived $archived session(s)"
}

# Main execution
function Main {
    Write-Host "RawrXD Chat Session Manager" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-SessionManager
    
    switch ($Action) {
        "List" { Show-SessionList }
        "New" { New-ChatSession -Id $SessionId -ModelName $Model }
        "Load" { Show-SessionDetails -Id $SessionId }
        "Delete" { Remove-SessionFile -Id $SessionId }
        "Export" { Export-SessionData -Id $SessionId -Path $ExportPath }
        "Import" { Import-SessionData -Path $ImportPath }
        "Archive" { Archive-OldSessions }
    }
    
    Write-Host ""
}

Main
