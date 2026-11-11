#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Teams Notification Script for RawrXD CI/CD

.DESCRIPTION
    Sends notifications to Microsoft Teams for CI/CD events:
    - Build status updates
    - Deployment notifications
    - Release announcements
    - Security alerts

.EXAMPLE
    .\scripts\notify_teams.ps1 -Status succeeded -Message "Build complete"
    .\scripts\notify_teams.ps1 -Status failed -Message "Tests failed" -MentionChannel

.NOTES
    Part of RawrXD Phase AB: CI/CD Pipeline & Automation
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("succeeded", "failed", "warning", "started", "cancelled")]
    [string]$Status,

    [Parameter()]
    [string]$Title = "RawrXD CI/CD Notification",

    [Parameter()]
    [string]$Message = "",

    [Parameter()]
    [string]$WebhookUrl = $env:TEAMS_WEBHOOK_URL,

    [Parameter()]
    [switch]$MentionChannel,

    [Parameter()]
    [hashtable]$Details = @{},

    [Parameter()]
    [string]$BuildUrl = $env:BUILD_URL,

    [Parameter()]
    [string]$CommitSha = $env:GITHUB_SHA,

    [Parameter()]
    [string]$Branch = $env:GITHUB_REF_NAME
)

# ============================================================================
# Configuration
# ============================================================================

$StatusConfig = @{
    succeeded = @{ Color = "00FF00"; Icon = "✅" }
    failed = @{ Color = "FF0000"; Icon = "❌" }
    warning = @{ Color = "FFA500"; Icon = "⚠️" }
    started = @{ Color = "0076D7"; Icon = "🚀" }
    cancelled = @{ Color = "808080"; Icon = "🚫" }
}

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Level = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Level] " -ForegroundColor $colors[$Level] -NoNewline
    Write-Host $Message
}

function Get-BuildFacts {
    $facts = @()

    if ($Branch) {
        $facts += @{
            name = "Branch"
            value = $Branch
        }
    }

    if ($CommitSha) {
        $shortSha = $CommitSha.Substring(0, 7)
        $facts += @{
            name = "Commit"
            value = $shortSha
        }
    }

    if ($BuildUrl) {
        $facts += @{
            name = "Build"
            value = "[View Build]($BuildUrl)"
        }
    }

    # Add custom details
    foreach ($key in $Details.Keys) {
        $facts += @{
            name = $key
            value = $Details[$key]
        }
    }

    return $facts
}

function Send-TeamsNotification {
    if ([string]::IsNullOrEmpty($WebhookUrl)) {
        Write-Status "No webhook URL provided. Set TEAMS_WEBHOOK_URL environment variable." "Warning"
        return $false
    }

    $config = $StatusConfig[$Status]

    $card = @{
        "@type" = "MessageCard"
        "@context" = "https://schema.org/extensions"
        themeColor = $config.Color
        summary = "$($config.Icon) $Title"
        sections = @(
            @{
                activityTitle = "$($config.Icon) $Title"
                activitySubtitle = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                facts = Get-BuildFacts
                text = $Message
                markdown = $true
            }
        )
        potentialAction = @(
            @{
                "@type" = "OpenUri"
                name = "View Build"
                targets = @(
                    @{
                        os = "default"
                        uri = if ($BuildUrl) { $BuildUrl } else { "https://github.com/ItsMehRAWRXD/RawrXD" }
                    }
                )
            }
        )
    }

    if ($MentionChannel) {
        $card.sections[0].text += "`n`n@channel"
    }

    $body = $card | ConvertTo-Json -Depth 10

    try {
        $response = Invoke-RestMethod -Uri $WebhookUrl -Method Post -ContentType "application/json" -Body $body
        Write-Status "Notification sent to Teams" "Success"
        return $true
    } catch {
        Write-Status "Failed to send notification: $_" "Error"
        return $false
    }
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Teams Notification" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Status "Status: $Status" "Info"
    Write-Status "Title: $Title" "Info"
    if ($Message) {
        Write-Status "Message: $Message" "Info"
    }
    Write-Status ""

    $success = Send-TeamsNotification

    if ($success) {
        exit 0
    } else {
        exit 1
    }
}

# Run main
Main
