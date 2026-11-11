# RawrXD Support Ticket System
# Phase P.1 - Post-Production Support & Maintenance
# Manages customer support tickets and issue tracking

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("create", "list", "update", "resolve", "escalate", "report")]
    [string]$Action = "list",

    [Parameter(Mandatory=$false)]
    [string]$TicketId = "",

    [Parameter(Mandatory=$false)]
    [string]$Subject = "",

    [Parameter(Mandatory=$false)]
    [string]$Description = "",

    [Parameter(Mandatory=$false)]
    [ValidateSet("P1", "P2", "P3", "P4")]
    [string]$Priority = "P3",

    [Parameter(Mandatory=$false)]
    [string]$CustomerEmail = "",

    [Parameter(Mandatory=$false)]
    [string]$Assignee = "",

    [Parameter(Mandatory=$false)]
    [string]$Comment = ""
)

$ErrorActionPreference = "Stop"

# Ticket storage
$TicketDbPath = "$env:USERPROFILE\.rawrxd\tickets"
if (!(Test-Path $TicketDbPath)) {
    New-Item -ItemType Directory -Path $TicketDbPath -Force | Out-Null
}

# Logging
function Write-SupportLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{ "INFO" = "White"; "SUCCESS" = "Green"; "WARNING" = "Yellow"; "ERROR" = "Red"; "TICKET" = "Cyan" }
    Write-Host "[$timestamp] [SUPPORT] [$Level] $Message" -ForegroundColor $colors[$Level]
}

# Ticket class
class SupportTicket {
    [string]$Id
    [string]$Subject
    [string]$Description
    [string]$Priority
    [string]$Status
    [string]$CustomerEmail
    [string]$Assignee
    [DateTime]$CreatedAt
    [DateTime]$UpdatedAt
    [DateTime]$ResolvedAt
    [array]$Comments
    [hashtable]$Metadata

    SupportTicket([string]$subject, [string]$description, [string]$priority, [string]$customerEmail) {
        $this.Id = "RXD-$(Get-Date -Format 'yyyyMMdd')-$(Get-Random -Minimum 1000 -Maximum 9999)"
        $this.Subject = $subject
        $this.Description = $description
        $this.Priority = $priority
        $this.Status = "open"
        $this.CustomerEmail = $customerEmail
        $this.Assignee = "unassigned"
        $this.CreatedAt = Get-Date
        $this.UpdatedAt = Get-Date
        $this.Comments = @()
        $this.Metadata = @{
            source = "powershell"
            version = "1.0.0"
        }
    }

    [void] AddComment([string]$author, [string]$text, [string]$visibility = "public") {
        $this.Comments += @{
            id = [Guid]::NewGuid().ToString()
            author = $author
            text = $text
            visibility = $visibility
            timestamp = Get-Date -Format "o"
        }
        $this.UpdatedAt = Get-Date
    }

    [hashtable] ToHashtable() {
        return @{
            id = $this.Id
            subject = $this.Subject
            description = $this.Description
            priority = $this.Priority
            status = $this.Status
            customer_email = $this.CustomerEmail
            assignee = $this.Assignee
            created_at = $this.CreatedAt.ToString("o")
            updated_at = $this.UpdatedAt.ToString("o")
            resolved_at = if ($this.ResolvedAt) { $this.ResolvedAt.ToString("o") } else { $null }
            comments = $this.Comments
            metadata = $this.Metadata
        }
    }
}

# Save ticket to database
function Save-Ticket {
    param([SupportTicket]$Ticket)

    $ticketPath = Join-Path $TicketDbPath "$($Ticket.Id).json"
    $Ticket.ToHashtable() | ConvertTo-Json -Depth 10 | Out-File $ticketPath -Encoding UTF8
}

# Load ticket from database
function Get-TicketFromDb {
    param([string]$Id)

    $ticketPath = Join-Path $TicketDbPath "$Id.json"
    if (Test-Path $ticketPath) {
        return Get-Content $ticketPath -Raw | ConvertFrom-Json
    }
    return $null
}

# Get all tickets
function Get-AllTickets {
    $tickets = @()
    $ticketFiles = Get-ChildItem -Path $TicketDbPath -Filter "*.json"

    foreach ($file in $ticketFiles) {
        $ticket = Get-Content $file.FullName -Raw | ConvertFrom-Json
        $tickets += $ticket
    }

    return $tickets | Sort-Object created_at -Descending
}

# Create new ticket
function New-SupportTicket {
    param(
        [string]$Subject,
        [string]$Description,
        [string]$Priority,
        [string]$CustomerEmail
    )

    Write-SupportLog "Creating new ticket: $Subject" "TICKET"

    $ticket = [SupportTicket]::new($Subject, $Description, $Priority, $CustomerEmail)

    # Auto-assign based on priority
    switch ($Priority) {
        "P1" { $ticket.Assignee = "senior-oncall" }
        "P2" { $ticket.Assignee = "support-team" }
        default { $ticket.Assignee = "support-queue" }
    }

    # Add initial comment
    $ticket.AddComment("system", "Ticket created automatically. Priority: $Priority", "internal")

    Save-Ticket -Ticket $ticket

    # Send notification (simulated)
    Write-SupportLog "Notification sent to $($ticket.Assignee)" "INFO"

    Write-SupportLog "Ticket created: $($ticket.Id)" "SUCCESS"
    return $ticket
}

# Update ticket
function Update-SupportTicket {
    param(
        [string]$Id,
        [string]$Status,
        [string]$Assignee,
        [string]$Comment
    )

    Write-SupportLog "Updating ticket: $Id" "TICKET"

    $ticketData = Get-TicketFromDb -Id $Id
    if (!$ticketData) {
        throw "Ticket not found: $Id"
    }

    $ticket = [SupportTicket]::new($ticketData.subject, $ticketData.description, $ticketData.priority, $ticketData.customer_email)
    $ticket.Id = $ticketData.id
    $ticket.Status = $ticketData.status
    $ticket.Assignee = $ticketData.assignee
    $ticket.CreatedAt = [DateTime]$ticketData.created_at
    $ticket.Comments = $ticketData.comments

    if ($Status) {
        $oldStatus = $ticket.Status
        $ticket.Status = $Status
        $ticket.UpdatedAt = Get-Date

        if ($Status -eq "resolved") {
            $ticket.ResolvedAt = Get-Date
        }

        Write-SupportLog "Status changed: $oldStatus -> $Status" "INFO"
    }

    if ($Assignee) {
        $ticket.Assignee = $Assignee
        $ticket.UpdatedAt = Get-Date
        Write-SupportLog "Assigned to: $Assignee" "INFO"
    }

    if ($Comment) {
        $ticket.AddComment($env:USERNAME, $Comment, "public")
        Write-SupportLog "Comment added" "INFO"
    }

    Save-Ticket -Ticket $ticket
    Write-SupportLog "Ticket updated: $Id" "SUCCESS"
    return $ticket
}

# List tickets with filtering
function Get-SupportTickets {
    param(
        [string]$Status,
        [string]$Priority,
        [string]$Assignee
    )

    $tickets = Get-AllTickets

    if ($Status) {
        $tickets = $tickets | Where-Object { $_.status -eq $Status }
    }

    if ($Priority) {
        $tickets = $tickets | Where-Object { $_.priority -eq $Priority }
    }

    if ($Assignee) {
        $tickets = $tickets | Where-Object { $_.assignee -eq $Assignee }
    }

    return $tickets
}

# Generate support report
function Export-SupportReport {
    param([string]$OutputPath)

    $tickets = Get-AllTickets

    $report = @{
        generated_at = Get-Date -Format "o"
        summary = @{
            total_tickets = $tickets.Count
            open = ($tickets | Where-Object { $_.status -eq "open" }).Count
            in_progress = ($tickets | Where-Object { $_.status -eq "in_progress" }).Count
            resolved = ($tickets | Where-Object { $_.status -eq "resolved" }).Count
            p1 = ($tickets | Where-Object { $_.priority -eq "P1" }).Count
            p2 = ($tickets | Where-Object { $_.priority -eq "P2" }).Count
            p3 = ($tickets | Where-Object { $_.priority -eq "P3" }).Count
            p4 = ($tickets | Where-Object { $_.priority -eq "P4" }).Count
        }
        tickets = $tickets
    }

    $report | ConvertTo-Json -Depth 10 | Out-File $OutputPath -Encoding UTF8
    Write-SupportLog "Report saved to $OutputPath" "SUCCESS"
}

# Main execution
switch ($Action) {
    "create" {
        if (!$Subject -or !$Description -or !$CustomerEmail) {
            Write-SupportLog "Required parameters: Subject, Description, CustomerEmail" "ERROR"
            exit 1
        }
        $ticket = New-SupportTicket -Subject $Subject -Description $Description -Priority $Priority -CustomerEmail $CustomerEmail
        Write-Host "`nTicket Created:" -ForegroundColor Green
        Write-Host "  ID: $($ticket.Id)" -ForegroundColor Cyan
        Write-Host "  Subject: $($ticket.Subject)"
        Write-Host "  Priority: $($ticket.Priority)"
        Write-Host "  Assignee: $($ticket.Assignee)"
    }
    "list" {
        $tickets = Get-SupportTickets -Status $Status -Priority $Priority -Assignee $Assignee
        if ($tickets.Count -gt 0) {
            Write-Host "`nSupport Tickets:" -ForegroundColor Cyan
            $tickets | Select-Object -First 20 | ForEach-Object {
                $color = switch ($_.priority) {
                    "P1" { "Red" }
                    "P2" { "Yellow" }
                    default { "White" }
                }
                Write-Host "[$($_.id)] " -NoNewline
                Write-Host "$($_.priority)" -ForegroundColor $color -NoNewline
                Write-Host " [$($_.status)] $($_.subject.Substring(0, [Math]::Min(50, $_.subject.Length)))"
            }
        } else {
            Write-SupportLog "No tickets found" "INFO"
        }
    }
    "update" {
        if (!$TicketId) {
            Write-SupportLog "TicketId required" "ERROR"
            exit 1
        }
        Update-SupportTicket -Id $TicketId -Status $Status -Assignee $Assignee -Comment $Comment
    }
    "resolve" {
        if (!$TicketId) {
            Write-SupportLog "TicketId required" "ERROR"
            exit 1
        }
        Update-SupportTicket -Id $TicketId -Status "resolved" -Comment $Comment
    }
    "escalate" {
        if (!$TicketId) {
            Write-SupportLog "TicketId required" "ERROR"
            exit 1
        }
        $ticket = Update-SupportTicket -Id $TicketId -Priority "P1" -Assignee "senior-oncall" -Comment "Escalated to P1"
        Write-SupportLog "Ticket escalated to P1" "WARNING"
    }
    "report" {
        $reportPath = "support_report_$(Get-Date -Format 'yyyyMMdd').json"
        Export-SupportReport -OutputPath $reportPath
    }
}
