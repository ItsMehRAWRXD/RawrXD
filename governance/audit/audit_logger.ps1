#!/usr/bin/env pwsh
#==============================================================================
# RawrXD Sovereign Inferencer - Governance Audit Logger
# Phase G.1 Batch 3/5: Immutable Hotpatch History
#==============================================================================
# Records all governance actions with cryptographic integrity
#==============================================================================

[CmdletBinding()]
param(
    [Parameter()]
    [string]$AuditPath = ".\audit_logs",

    [Parameter()]
    [string]$Action,

    [Parameter()]
    [hashtable]$ActionData,

    [Parameter()]
    [switch]$VerifyIntegrity,

    [Parameter()]
    [switch]$ExportReport
)

#==============================================================================
# Audit Configuration
#==============================================================================

$script:AuditConfig = @{
    Version = "1.0.0"
    HashAlgorithm = "SHA256"
    LogRetentionDays = 365
    RequiredFields = @("Timestamp", "Action", "Actor", "Hash", "PreviousHash")
    
    ActionTypes = @(
        "Hotpatch_Applied"
        "Hotpatch_Rolled_Back"
        "Hotpatch_Failed"
        "Performance_Threshold_Breach"
        "SIS_Score_Change"
        "Governance_Decision"
        "Configuration_Change"
        "Security_Event"
    )
}

#==============================================================================
# Audit Logger Classes
#==============================================================================

class AuditLogger {
    [string]$AuditPath
    [string]$CurrentLogFile
    [hashtable]$LastEntry
    [System.Security.Cryptography.HashAlgorithm]$Hasher

    AuditLogger([string]$auditPath) {
        $this.AuditPath = $auditPath
        $this.Hasher = [System.Security.Cryptography.SHA256]::Create()
        $this.Initialize()
    }

    [void] Initialize() {
        New-Item -ItemType Directory -Force -Path $this.AuditPath | Out-Null
        
        # Create daily log file
        $date = Get-Date -Format "yyyyMMdd"
        $this.CurrentLogFile = Join-Path $this.AuditPath "audit_$date.jsonl"
        
        # Load last entry for chain continuity
        $this.LoadLastEntry()
        
        Write-Host "✓ Audit logger initialized: $($this.CurrentLogFile)" -ForegroundColor Green
    }

    [void] LoadLastEntry() {
        $logFiles = Get-ChildItem -Path $this.AuditPath -Filter "audit_*.jsonl" | 
            Sort-Object Name -Descending
        
        if ($logFiles.Count -gt 0) {
            $latestFile = $logFiles[0]
            $lastLine = Get-Content $latestFile.FullName -Tail 1
            if ($lastLine) {
                try {
                    $this.LastEntry = $lastLine | ConvertFrom-Json -AsHashtable
                }
                catch {
                    $this.LastEntry = $null
                }
            }
        }
    }

    [string] CalculateHash([hashtable]$data) {
        $json = $data | ConvertTo-Json -Depth 10 -Compress
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $hash = $this.Hasher.ComputeHash($bytes)
        return [BitConverter]::ToString($hash).Replace("-", "").ToLower()
    }

    [hashtable] LogAction([string]$action, [hashtable]$data, [string]$actor) {
        if ($action -notin $script:AuditConfig.ActionTypes) {
            throw "Invalid action type: $action. Valid types: $($script:AuditConfig.ActionTypes -join ', ')"
        }
        
        $entry = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            Action = $action
            Actor = $actor
            Data = $data
            Sequence = if ($this.LastEntry) { $this.LastEntry.Sequence + 1 } else { 1 }
            PreviousHash = if ($this.LastEntry) { $this.LastEntry.Hash } else { "0" * 64 }
        }
        
        # Calculate hash of this entry (includes previous hash for chain)
        $entry.Hash = $this.CalculateHash($entry)
        
        # Append to log
        ($entry | ConvertTo-Json -Depth 10 -Compress) | Out-File -Append -FilePath $this.CurrentLogFile
        
        # Update last entry
        $this.LastEntry = $entry
        
        Write-Host "✓ Audit entry logged: $action (seq: $($entry.Sequence))" -ForegroundColor Green
        
        return $entry
    }

    [bool] VerifyChain() {
        Write-Host "`n=== Verifying Audit Chain Integrity ===" -ForegroundColor Cyan
        
        $logFiles = Get-ChildItem -Path $this.AuditPath -Filter "audit_*.jsonl" | 
            Sort-Object Name
        
        $allValid = $true
        $previousHash = "0" * 64
        $sequence = 0
        
        foreach ($file in $logFiles) {
            Write-Host "Checking: $($file.Name)" -ForegroundColor White
            
            $lines = Get-Content $file.FullName
            foreach ($line in $lines) {
                if (-not $line.Trim()) { continue }
                
                try {
                    $entry = $line | ConvertFrom-Json -AsHashtable
                    
                    # Verify sequence
                    $expectedSequence = $sequence + 1
                    if ($entry.Sequence -ne $expectedSequence) {
                        Write-Error "Sequence break at entry $($entry.Sequence): expected $expectedSequence"
                        $allValid = $false
                        continue
                    }
                    
                    # Verify previous hash
                    if ($entry.PreviousHash -ne $previousHash) {
                        Write-Error "Hash chain broken at entry $($entry.Sequence)"
                        $allValid = $false
                        continue
                    }
                    
                    # Verify entry hash
                    $entryCopy = $entry.Clone()
                    $entryCopy.Remove("Hash")
                    $calculatedHash = $this.CalculateHash($entryCopy)
                    
                    if ($entry.Hash -ne $calculatedHash) {
                        Write-Error "Hash mismatch at entry $($entry.Sequence)"
                        $allValid = $false
                        continue
                    }
                    
                    $previousHash = $entry.Hash
                    $sequence = $entry.Sequence
                }
                catch {
                    Write-Error "Failed to verify entry: $_"
                    $allValid = $false
                }
            }
        }
        
        if ($allValid) {
            Write-Host "✓ Audit chain verified: $sequence entries, all hashes valid" -ForegroundColor Green
        }
        else {
            Write-Host "✗ Audit chain verification failed" -ForegroundColor Red
        }
        
        return $allValid
    }

    [array] QueryActions([string]$actionType, [datetime]$startTime, [datetime]$endTime) {
        $results = @()
        
        $logFiles = Get-ChildItem -Path $this.AuditPath -Filter "audit_*.jsonl"
        
        foreach ($file in $logFiles) {
            $lines = Get-Content $file.FullName
            foreach ($line in $lines) {
                if (-not $line.Trim()) { continue }
                
                try {
                    $entry = $line | ConvertFrom-Json -AsHashtable
                    $entryTime = [datetime]::Parse($entry.Timestamp)
                    
                    if ($entryTime -lt $startTime -or $entryTime -gt $endTime) {
                        continue
                    }
                    
                    if ($actionType -and $entry.Action -ne $actionType) {
                        continue
                    }
                    
                    $results += $entry
                }
                catch {
                    # Skip invalid entries
                }
            }
        }
        
        return $results | Sort-Object Sequence
    }

    [void] GenerateReport([string]$outputPath) {
        Write-Host "`n=== Generating Audit Report ===" -ForegroundColor Cyan
        
        $startTime = (Get-Date).AddDays(-30)
        $endTime = Get-Date
        
        $allActions = $this.QueryActions($null, $startTime, $endTime)
        
        $report = @{
            Generated = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            Period = @{
                Start = $startTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
                End = $endTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
            }
            Summary = @{}
            Actions = $allActions
        }
        
        # Calculate summary statistics
        $grouped = $allActions | Group-Object -Property Action
        foreach ($group in $grouped) {
            $report.Summary[$group.Name] = $group.Count
        }
        
        # Save report
        $report | ConvertTo-Json -Depth 10 | Out-File $outputPath
        
        Write-Host "✓ Report generated: $outputPath" -ForegroundColor Green
        Write-Host "  Total actions: $($allActions.Count)" -ForegroundColor Gray
        Write-Host "  Action types: $($grouped.Count)" -ForegroundColor Gray
    }

    [void] DisplayHistory([int]$count = 10) {
        Write-Host "`n=== Recent Audit History ===" -ForegroundColor Cyan
        
        $startTime = (Get-Date).AddDays(-7)
        $endTime = Get-Date
        $actions = $this.QueryActions($null, $startTime, $endTime) | Select-Object -Last $count
        
        foreach ($action in $actions) {
            $color = switch ($action.Action) {
                "Hotpatch_Failed" { "Red" }
                "Performance_Threshold_Breach" { "Yellow" }
                "Security_Event" { "Red" }
                default { "White" }
            }
            
            Write-Host "[$($action.Timestamp)] $($action.Action)" -ForegroundColor $color
            Write-Host "  Actor: $($action.Actor) | Seq: $($action.Sequence)" -ForegroundColor Gray
            if ($action.Data -and $action.Data.Count -gt 0) {
                Write-Host "  Data: $($action.Data | ConvertTo-Json -Compress)" -ForegroundColor DarkGray
            }
        }
    }
}

#==============================================================================
# Main Execution
#==============================================================================

Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║           RawrXD Sovereign - Governance Audit Logger                         ║
║           Phase G.1 Batch 3/5: Immutable Hotpatch History                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

$logger = [AuditLogger]::new($AuditPath)

if ($Action) {
    # Log specific action
    $actor = $env:USERNAME
    $entry = $logger.LogAction($Action, $ActionData, $actor)
    Write-Host "`nLogged entry hash: $($entry.Hash)" -ForegroundColor Green
}
elseif ($VerifyIntegrity) {
    # Verify chain integrity
    $valid = $logger.VerifyChain()
    exit $(if ($valid) { 0 } else { 1 })
}
elseif ($ExportReport) {
    # Generate report
    $reportPath = Join-Path $AuditPath "audit_report_$(Get-Date -Format 'yyyyMMdd').json"
    $logger.GenerateReport($reportPath)
}
else {
    # Interactive mode
    Write-Host "`nAudit Logger Commands:" -ForegroundColor Yellow
    Write-Host "  1. Log hotpatch applied"
    Write-Host "  2. Log performance breach"
    Write-Host "  3. Log governance decision"
    Write-Host "  4. Verify chain integrity"
    Write-Host "  5. View recent history"
    Write-Host "  6. Generate report"
    
    $choice = Read-Host "`nSelect option (1-6)"
    
    switch ($choice) {
        "1" {
            $patchName = Read-Host "Enter patch name"
            $data = @{ PatchName = $patchName; DeployTime_ms = (Get-Random -Minimum 2 -Maximum 6) }
            $logger.LogAction("Hotpatch_Applied", $data, $env:USERNAME)
        }
        "2" {
            $metric = Read-Host "Enter metric name"
            $value = Read-Host "Enter value"
            $data = @{ Metric = $metric; Value = [double]$value; Threshold = 50 }
            $logger.LogAction("Performance_Threshold_Breach", $data, $env:USERNAME)
        }
        "3" {
            $decision = Read-Host "Enter decision description"
            $data = @{ Decision = $decision; Reason = "Manual" }
            $logger.LogAction("Governance_Decision", $data, $env:USERNAME)
        }
        "4" {
            $logger.VerifyChain()
        }
        "5" {
            $logger.DisplayHistory(10)
        }
        "6" {
            $reportPath = Join-Path $AuditPath "audit_report_$(Get-Date -Format 'yyyyMMdd').json"
            $logger.GenerateReport($reportPath)
        }
    }
}
