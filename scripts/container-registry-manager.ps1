# RawrXD Container Registry Manager
# Manages container images, tags, and cleanup policies
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [ValidateSet("List", "Push", "Pull", "Clean", "Scan")]
    [string]$Action = "List",
    
    [Parameter()]
    [string]$ImageName,
    
    [Parameter()]
    [string]$Tag = "latest",
    
    [Parameter()]
    [string]$Registry = "registry.rawrxd.local",
    
    [Parameter()]
    [int]$KeepLast = 10
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

function Get-RegistryData {
    return @{
        Images = @(
            @{ Name = "rawrxd/api"; Tags = @("v1.0.0", "v1.0.1", "v1.1.0", "latest"); SizeGB = 1.2; LastPushed = (Get-Date).AddDays(-1).ToString("o") }
            @{ Name = "rawrxd/web"; Tags = @("v2.0.0", "v2.0.1", "v2.1.0", "latest"); SizeGB = 0.8; LastPushed = (Get-Date).AddDays(-2).ToString("o") }
            @{ Name = "rawrxd/worker"; Tags = @("v1.0.0", "v1.0.5", "latest"); SizeGB = 2.1; LastPushed = (Get-Date).AddDays(-3).ToString("o") }
        )
        TotalSizeGB = 4.1
        TotalImages = 3
    }
}

function Show-RegistryList {
    $data = Get-RegistryData
    
    Write-Host "`n🐳 Container Registry" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Registry: $Registry"
    Write-Host "Total Images: $($data.TotalImages)"
    Write-Host "Total Size: $($data.TotalSizeGB) GB"
    Write-Host ""
    
    Write-Host "Images:" -ForegroundColor Yellow
    Write-Host "Repository          Tags    Size      Last Pushed"
    Write-Host "----------          ----    ----      -----------"
    
    foreach ($image in $data.Images) {
        Write-Host ($image.Name).PadRight(20) -NoNewline
        Write-Host ($image.Tags.Count.ToString()).PadRight(8) -NoNewline
        Write-Host "$($image.SizeGB) GB".PadRight(10) -NoNewline
        Write-Host ([datetime]$image.LastPushed).ToString("yyyy-MM-dd")
    }
    Write-Host ""
}

function Invoke-ImagePush {
    if (-not $ImageName) {
        throw "ImageName parameter required for Push action"
    }
    
    Write-Host "`n📤 Pushing Container Image" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host ""
    
    $fullImageName = "$Registry/$ImageName`:$Tag"
    
    Write-Status "Image: $fullImageName"
    Write-Host ""
    
    Write-Status "Building image..."
    Write-Host "  Sending build context..." -NoNewline
    Start-Sleep -Seconds 1
    Write-Host " ✓" -ForegroundColor Green
    
    Write-Host "  Building layers..." -NoNewline
    Start-Sleep -Seconds 2
    Write-Host " ✓" -ForegroundColor Green
    
    Write-Status "Pushing to registry..."
    Write-Host "  Layer 1/5..." -NoNewline
    Start-Sleep -Milliseconds 500
    Write-Host " ✓" -ForegroundColor Green
    
    Write-Host "  Layer 2/5..." -NoNewline
    Start-Sleep -Milliseconds 500
    Write-Host " ✓" -ForegroundColor Green
    
    Write-Host "  Layer 3/5..." -NoNewline
    Start-Sleep -Milliseconds 500
    Write-Host " ✓" -ForegroundColor Green
    
    Write-Host "  Layer 4/5..." -NoNewline
    Start-Sleep -Milliseconds 500
    Write-Host " ✓" -ForegroundColor Green
    
    Write-Host "  Layer 5/5..." -NoNewline
    Start-Sleep -Milliseconds 500
    Write-Host " ✓" -ForegroundColor Green
    
    Write-Host ""
    Write-Success "Image pushed successfully!"
    Write-Status "Location: $fullImageName"
}

function Invoke-RegistryCleanup {
    Write-Host "`n🧹 Registry Cleanup" -ForegroundColor Cyan
    Write-Host "===================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Status "Cleanup Policy: Keep last $KeepLast tags per image"
    Write-Host ""
    
    $data = Get-RegistryData
    $removed = 0
    $savedSpace = 0
    
    foreach ($image in $data.Images) {
        $tagCount = $image.Tags.Count
        if ($tagCount -gt $KeepLast) {
            $toRemove = $tagCount - $KeepLast
            Write-Status "Removing $toRemove old tags from $($image.Name)..."
            $removed += $toRemove
            $savedSpace += ($image.SizeGB / $tagCount) * $toRemove
        }
    }
    
    Write-Host ""
    Write-Success "Cleanup complete!"
    Write-Status "Removed: $removed tag(s)"
    Write-Status "Space saved: $([math]::Round($savedSpace, 2)) GB"
}

function Invoke-ImageScan {
    if (-not $ImageName) {
        throw "ImageName parameter required for Scan action"
    }
    
    Write-Host "`n🔍 Scanning Container Image" -ForegroundColor Cyan
    Write-Host "==========================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Status "Image: $Registry/$ImageName`:$Tag"
    Write-Host ""
    
    Write-Status "Downloading image layers..."
    Start-Sleep -Seconds 1
    Write-Success "  ✓ Layers downloaded"
    
    Write-Status "Scanning for vulnerabilities..."
    Start-Sleep -Seconds 2
    
    # Simulate findings
    $findings = @(
        @{ Severity = "Critical"; Count = 0 }
        @{ Severity = "High"; Count = 2 }
        @{ Severity = "Medium"; Count = 5 }
        @{ Severity = "Low"; Count = 12 }
    )
    
    Write-Host ""
    Write-Host "Scan Results:" -ForegroundColor Yellow
    foreach ($finding in $findings) {
        $color = switch ($finding.Severity) {
            "Critical" { "Red" }
            "High" { "Red" }
            "Medium" { "Yellow" }
            default { "Green" }
        }
        Write-Host "  $($finding.Severity): $($finding.Count)" -ForegroundColor $color
    }
    
    Write-Host ""
    Write-Success "Scan complete!"
}

# Main execution
try {
    switch ($Action) {
        "List" { Show-RegistryList }
        "Push" { Invoke-ImagePush }
        "Pull" { Write-Status "Would pull image from registry" }
        "Clean" { Invoke-RegistryCleanup }
        "Scan" { Invoke-ImageScan }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
