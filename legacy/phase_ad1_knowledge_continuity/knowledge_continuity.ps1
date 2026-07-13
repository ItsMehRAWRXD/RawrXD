#!/usr/bin/env pwsh
#requires -Version 7.0
# Phase AD.1: Knowledge Continuity System
# Ensures organizational knowledge persists and evolves

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("capture", "transfer", "validate", "mentor", "archive", "restore")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$Expert,
    
    [Parameter(Mandatory=$false)]
    [string]$Mentee,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\knowledge"
)

$ErrorActionPreference = "Stop"

# Knowledge registry
$KnowledgeRegistry = @{
    Domains = @{}
    Experts = @()
    Transfers = @()
    Archives = @()
    LastUpdated = $null
}

# Knowledge domains
$KnowledgeDomains = @{
    Architecture = @{
        Criticality = "Critical"
        BusFactor = 2
        Documents = @("architecture", "decisions", "patterns")
    }
    Security = @{
        Criticality = "Critical"
        BusFactor = 3
        Documents = @("threat-models", "audits", "procedures")
    }
    AI_ML = @{
        Criticality = "Critical"
        BusFactor = 2
        Documents = @("models", "training", "inference")
    }
    Operations = @{
        Criticality = "High"
        BusFactor = 3
        Documents = @("runbooks", "procedures", "troubleshooting")
    }
    Business = @{
        Criticality = "High"
        BusFactor = 2
        Documents = @("strategy", "partnerships", "roadmap")
    }
}

function Write-KnowledgeHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase AD.1: Knowledge Continuity System                         ║
║  Preserving and transferring organizational wisdom                 ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-KnowledgeSystem {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    # Initialize domain directories
    foreach ($domain in $KnowledgeDomains.Keys) {
        $domainPath = Join-Path $OutputPath $domain
        if (-not (Test-Path $domainPath)) {
            New-Item -ItemType Directory -Path $domainPath -Force | Out-Null
            
            foreach ($docType in $KnowledgeDomains[$domain].Documents) {
                New-Item -ItemType Directory -Path (Join-Path $domainPath $docType) -Force | Out-Null
            }
        }
    }
    
    # Load registry
    $registryFile = Join-Path $OutputPath "knowledge_registry.json"
    if (Test-Path $registryFile) {
        $script:KnowledgeRegistry = Get-Content -Path $registryFile -Raw | ConvertFrom-Json -AsHashtable
    }
}

function Save-KnowledgeRegistry {
    $script:KnowledgeRegistry.LastUpdated = Get-Date -Format "o"
    $registryFile = Join-Path $OutputPath "knowledge_registry.json"
    $script:KnowledgeRegistry | ConvertTo-Json -Depth 10 | Set-Content -Path $registryFile
}

function Invoke-KnowledgeCapture {
    param($Domain, $Expert)
    
    Write-Host "`nCapturing knowledge for domain: $Domain" -ForegroundColor Yellow
    
    if (-not $KnowledgeDomains.ContainsKey($Domain)) {
        Write-Error "Unknown domain: $Domain"
        return
    }
    
    $domainConfig = $KnowledgeDomains[$Domain]
    $captureSession = @{
        Domain = $Domain
        Expert = $Expert
        CapturedAt = Get-Date -Format "o"
        Artifacts = @()
    }
    
    # Capture each document type
    foreach ($docType in $domainConfig.Documents) {
        Write-Host "  Capturing $docType..." -ForegroundColor Gray
        
        $artifact = @{
            Type = $docType
            Content = "Knowledge from $Expert on $Domain/$docType"
            CreatedAt = Get-Date -Format "o"
            Expert = $Expert
        }
        
        $artifactPath = Join-Path (Join-Path $OutputPath $Domain) "$docType\$($Expert)_$(Get-Date -Format 'yyyyMMdd').json"
        $artifact | ConvertTo-Json | Set-Content -Path $artifactPath
        
        $captureSession.Artifacts += $artifact
        Write-Host "    ✓ Captured: $docType" -ForegroundColor Green
    }
    
    # Register expert
    $existingExpert = $script:KnowledgeRegistry.Experts | Where-Object { $_.Name -eq $Expert }
    if (-not $existingExpert) {
        $script:KnowledgeRegistry.Experts += @{
            Name = $Expert
            Domains = @($Domain)
            JoinedAt = Get-Date -Format "o"
        }
    } else {
        if ($existingExpert.Domains -notcontains $Domain) {
            $existingExpert.Domains += $Domain
        }
    }
    
    # Update domain
    if (-not $script:KnowledgeRegistry.Domains.ContainsKey($Domain)) {
        $script:KnowledgeRegistry.Domains[$Domain] = @{
            Experts = @()
            Captures = @()
        }
    }
    
    $script:KnowledgeRegistry.Domains[$Domain].Experts += $Expert
    $script:KnowledgeRegistry.Domains[$Domain].Captures += $captureSession
    
    Save-KnowledgeRegistry
    
    Write-Host "`n✓ Knowledge capture complete" -ForegroundColor Green
    Write-Host "  Artifacts: $($captureSession.Artifacts.Count)" -ForegroundColor Cyan
    Write-Host "  Expert: $Expert" -ForegroundColor Cyan
}

function Invoke-KnowledgeTransfer {
    param($Domain, $Expert, $Mentee)
    
    Write-Host "`nInitiating knowledge transfer..." -ForegroundColor Yellow
    Write-Host "  Domain: $Domain" -ForegroundColor Gray
    Write-Host "  From: $Expert" -ForegroundColor Gray
    Write-Host "  To: $Mentee" -ForegroundColor Gray
    
    $transfer = @{
        Id = [Guid]::NewGuid().ToString()
        Domain = $Domain
        Expert = $Expert
        Mentee = $Mentee
        StartedAt = Get-Date -Format "o"
        Status = "active"
        Phases = @(
            @{ Name = "Orientation"; Status = "completed"; CompletedAt = Get-Date -Format "o" },
            @{ Name = "Shadowing"; Status = "in-progress"; StartedAt = Get-Date -Format "o" },
            @{ Name = "Guided Practice"; Status = "pending" },
            @{ Name = "Independent Execution"; Status = "pending" },
            @{ Name = "Validation"; Status = "pending" }
        )
    }
    
    $script:KnowledgeRegistry.Transfers += $transfer
    Save-KnowledgeRegistry
    
    Write-Host "`n✓ Knowledge transfer initiated" -ForegroundColor Green
    Write-Host "  Transfer ID: $($transfer.Id)" -ForegroundColor Cyan
    Write-Host "`nTransfer Plan:" -ForegroundColor Yellow
    foreach ($phase in $transfer.Phases) {
        $statusIcon = switch ($phase.Status) {
            "completed" { "✓" }
            "in-progress" { "▶" }
            default { "○" }
        }
        Write-Host "  $statusIcon $($phase.Name)" -ForegroundColor $(if ($phase.Status -eq "completed") { "Green" } elseif ($phase.Status -eq "in-progress") { "Yellow" } else { "Gray" })
    }
}

function Get-KnowledgeStatus {
    Write-Host "`nKnowledge Continuity Status" -ForegroundColor Yellow
    Write-Host ""
    
    # Domain coverage
    Write-Host "Domain Coverage:" -ForegroundColor White
    foreach ($domain in $KnowledgeDomains.Keys) {
        $config = $KnowledgeDomains[$domain]
        $experts = @()
        if ($script:KnowledgeRegistry.Domains.ContainsKey($domain)) {
            $experts = $script:KnowledgeRegistry.Domains[$domain].Experts | Select-Object -Unique
        }
        
        $busFactor = $experts.Count
        $statusColor = if ($busFactor -ge $config.BusFactor) { "Green" } elseif ($busFactor -gt 0) { "Yellow" } else { "Red" }
        $statusIcon = if ($busFactor -ge $config.BusFactor) { "✓" } elseif ($busFactor -gt 0) { "⚠" } else { "✗" }
        
        Write-Host "  $statusIcon $domain : Bus Factor $busFactor/$($config.BusFactor)" -ForegroundColor $statusColor
        if ($experts.Count -gt 0) {
            Write-Host "      Experts: $($experts -join ', ')" -ForegroundColor Gray
        }
    }
    
    # Active transfers
    Write-Host "`nActive Transfers:" -ForegroundColor White
    $active = $script:KnowledgeRegistry.Transfers | Where-Object { $_.Status -eq "active" }
    if ($active.Count -eq 0) {
        Write-Host "  None" -ForegroundColor Gray
    } else {
        foreach ($transfer in $active) {
            $currentPhase = $transfer.Phases | Where-Object { $_.Status -eq "in-progress" } | Select-Object -First 1
            Write-Host "  $($transfer.Domain): $($transfer.Expert) → $($transfer.Mentee)" -ForegroundColor Cyan
            Write-Host "      Phase: $($currentPhase.Name)" -ForegroundColor Gray
        }
    }
    
    # Risk assessment
    Write-Host "`nRisk Assessment:" -ForegroundColor White
    $atRisk = $KnowledgeDomains.Keys | Where-Object {
        $domain = $_
        $config = $KnowledgeDomains[$domain]
        $experts = @()
        if ($script:KnowledgeRegistry.Domains.ContainsKey($domain)) {
            $experts = $script:KnowledgeRegistry.Domains[$domain].Experts | Select-Object -Unique
        }
        return $experts.Count -lt $config.BusFactor
    }
    
    if ($atRisk.Count -eq 0) {
        Write-Host "  ✓ All domains adequately covered" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ At-risk domains: $($atRisk -join ', ')" -ForegroundColor Yellow
    }
}

# Main execution
Write-KnowledgeHeader
Initialize-KnowledgeSystem

switch ($Action) {
    "capture" {
        if (-not $Domain -or -not $Expert) {
            Write-Error "Domain and Expert required for capture"
            exit 1
        }
        Invoke-KnowledgeCapture -Domain $Domain -Expert $Expert
    }
    "transfer" {
        if (-not $Domain -or -not $Expert -or -not $Mentee) {
            Write-Error "Domain, Expert, and Mentee required for transfer"
            exit 1
        }
        Invoke-KnowledgeTransfer -Domain $Domain -Expert $Expert -Mentee $Mentee
    }
    "validate" {
        Get-KnowledgeStatus
    }
    default {
        Write-Host "Usage: knowledge_continuity.ps1 -Action {capture|transfer|validate} ..." -ForegroundColor Yellow
    }
}

Write-Host "`n✅ Knowledge continuity operation complete" -ForegroundColor Green
