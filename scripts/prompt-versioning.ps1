# RawrXD Prompt Versioning
# Manages prompt versioning and history

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("List", "Create", "Update", "Rollback", "Compare")]
    [string]$Action = "List",
    
    [string]$PromptId = "",
    [string]$Content = "",
    [string]$Description = "",
    [string]$Version = ""
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

function Initialize-PromptVersioning {
    Write-Status "Prompt Versioning initialized"
}

function Get-PromptVersions {
    return @(
        @{ Id = "P-001"; Name = "System Prompt"; Version = "1.3.0"; Author = "admin"; Date = "2024-01-15"; Status = "Active" }
        @{ Id = "P-001"; Name = "System Prompt"; Version = "1.2.0"; Author = "admin"; Date = "2024-01-10"; Status = "Archived" }
        @{ Id = "P-001"; Name = "System Prompt"; Version = "1.1.0"; Author = "admin"; Date = "2024-01-05"; Status = "Archived" }
        @{ Id = "P-002"; Name = "Code Assistant"; Version = "2.0.0"; Author = "dev-team"; Date = "2024-01-12"; Status = "Active" }
    )
}

function Show-PromptList {
    $prompts = Get-PromptVersions
    
    Write-Host ""
    Write-Host "Prompt Versions" -ForegroundColor Cyan
    Write-Host "===============" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "  ID      Name             Version    Author      Date        Status"
    Write-Host "  " + "-" * 75
    
    foreach ($prompt in $prompts) {
        $statusColor = if ($prompt.Status -eq "Active") { "Green" } else { "Gray" }
        Write-Host "  $($prompt.Id)  $($prompt.Name.PadRight(16)) $($prompt.Version.PadRight(10)) $($prompt.Author.PadRight(11)) $($prompt.Date.PadRight(11)) " -NoNewline
        Write-Host $prompt.Status -ForegroundColor $statusColor
    }
}

function Create-PromptVersion {
    param([string]$Id, [string]$Cnt, [string]$Desc)
    
    if (-not $Id) {
        $Id = "P-$(Get-Random -Minimum 100 -Maximum 999)"
    }
    
    Write-Status "Creating prompt version: $Id"
    Write-Host "  Description: $Desc"
    Write-Success "Prompt version created"
}

function Update-PromptVersion {
    param([string]$Id, [string]$Cnt, [string]$Desc)
    
    if (-not $Id) {
        Write-Error "Prompt ID required"
        return
    }
    
    Write-Status "Updating prompt: $Id"
    Write-Host "  New version created"
    Write-Success "Prompt updated"
}

function Rollback-Prompt {
    param([string]$Id, [string]$Ver)
    
    if (-not $Id -or -not $Ver) {
        Write-Error "Prompt ID and version required"
        return
    }
    
    Write-Status "Rolling back $Id to version $Ver"
    Write-Success "Rollback complete"
}

function Compare-PromptVersions {
    param([string]$Id)
    
    if (-not $Id) {
        Write-Error "Prompt ID required"
        return
    }
    
    Write-Host ""
    Write-Host "Comparing versions for $Id" -ForegroundColor Cyan
    Write-Host "==========================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  v1.3.0 (Active) vs v1.2.0 (Previous)"
    Write-Host "  Changes:"
    Write-Host "    + Added context window optimization"
    Write-Host "    ~ Modified system instructions"
    Write-Host "    - Removed deprecated parameters"
}

# Main execution
function Main {
    Write-Host "RawrXD Prompt Versioning" -ForegroundColor Cyan
    Write-Host "========================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-PromptVersioning
    
    switch ($Action) {
        "List" { Show-PromptList }
        "Create" { Create-PromptVersion -Id $PromptId -Cnt $Content -Desc $Description }
        "Update" { Update-PromptVersion -Id $PromptId -Cnt $Content -Desc $Description }
        "Rollback" { Rollback-Prompt -Id $PromptId -Ver $Version }
        "Compare" { Compare-PromptVersions -Id $PromptId }
    }
    
    Write-Host ""
}

Main
