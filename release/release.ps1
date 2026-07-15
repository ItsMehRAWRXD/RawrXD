# RawrXD Release
# Phase I Batch 5/5: Production Release
# Executes the final release process

param(
    [Parameter()]
    [ValidateSet("Prepare", "Execute", "Publish", "Verify", "ShowStatus")]
    [string]$Action = "ShowStatus",
    
    [Parameter()]
    [string]$Version,
    
    [Parameter()]
    [string]$GitHubToken,
    
    [Parameter()]
    [switch]$Draft,
    
    [Parameter()]
    [switch]$Prerelease
)

# Release configuration
$ReleaseConfig = @{
    Repository = "ItsMehRAWRXD/RawrXD"
    ProductName = "RawrXD"
    DefaultBranch = "main"
    ArtifactsPath = "$PSScriptRoot\artifacts"
}

# State file
$StateFile = "$PSScriptRoot\release_state.json"

function Write-ReleaseLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    $logPath = "$PSScriptRoot\..\logs\release"
    if (-not (Test-Path $logPath)) {
        New-Item -ItemType Directory -Path $logPath -Force | Out-Null
    }
    $logFile = Join-Path $logPath "release_final_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "SUCCESS" { "Green" }
        "RELEASE" { "Cyan" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Get-ReleaseState {
    if (Test-Path $StateFile) {
        return Get-Content $StateFile | ConvertFrom-Json
    }
    return @{
        CurrentVersion = $null
        LastReleaseDate = $null
        Releases = @()
        PreparationComplete = $false
        ValidationComplete = $false
        PackagingComplete = $false
        DocumentationComplete = $false
        Released = $false
    }
}

function Save-ReleaseState {
    param($State)
    $State | ConvertTo-Json -Depth 10 | Out-File $StateFile -Encoding UTF8
}

function Invoke-ReleasePreparation {
    param([string]$Version)
    
    Write-ReleaseLog "Preparing release v$Version..." "RELEASE"
    
    # Run preparation script
    $prepScript = "$PSScriptRoot\release_preparation.ps1"
    if (Test-Path $prepScript) {
        & $prepScript -Action Prepare -Version $Version
        Write-ReleaseLog "Release preparation complete" "SUCCESS"
        return $true
    }
    else {
        Write-ReleaseLog "Preparation script not found" "ERROR"
        return $false
    }
}

function Invoke-ReleaseValidation {
    Write-ReleaseLog "Running release validation..." "RELEASE"
    
    $validationScript = "$PSScriptRoot\final_validation.ps1"
    if (Test-Path $validationScript) {
        $result = & $validationScript -ValidationType Full 2>$1
        if ($LASTEXITCODE -eq 0) {
            Write-ReleaseLog "Validation passed" "SUCCESS"
            return $true
        }
        else {
            Write-ReleaseLog "Validation failed" "ERROR"
            return $false
        }
    }
    else {
        Write-ReleaseLog "Validation script not found" "ERROR"
        return $false
    }
}

function Invoke-ReleasePackaging {
    param([string]$Version)
    
    Write-ReleaseLog "Creating release packages..." "RELEASE"
    
    $packageScript = "$PSScriptRoot\packaging.ps1"
    if (Test-Path $packageScript) {
        & $packageScript -Action Create -Version $Version -PackageType All
        Write-ReleaseLog "Packaging complete" "SUCCESS"
        return $true
    }
    else {
        Write-ReleaseLog "Packaging script not found" "ERROR"
        return $false
    }
}

function Invoke-ReleaseDocumentation {
    param([string]$Version)
    
    Write-ReleaseLog "Finalizing documentation..." "RELEASE"
    
    $docsScript = "$PSScriptRoot\documentation_finalization.ps1"
    if (Test-Path $docsScript) {
        & $docsScript -Action Generate -Version $Version
        & $docsScript -Action Validate
        Write-ReleaseLog "Documentation finalized" "SUCCESS"
        return $true
    }
    else {
        Write-ReleaseLog "Documentation script not found" "ERROR"
        return $false
    }
}

function Invoke-FullRelease {
    param([string]$Version)
    
    Write-ReleaseLog "Starting full release process for v$Version..." "RELEASE"
    
    $state = Get-ReleaseState
    $startTime = Get-Date
    
    # Step 1: Preparation
    if (-not $state.PreparationComplete) {
        Write-ReleaseLog "Step 1/5: Release Preparation..." "RELEASE"
        $state.PreparationComplete = Invoke-ReleasePreparation -Version $Version
        Save-ReleaseState -State $state
        if (-not $state.PreparationComplete) { throw "Preparation failed" }
    }
    
    # Step 2: Validation
    if (-not $state.ValidationComplete) {
        Write-ReleaseLog "Step 2/5: Final Validation..." "RELEASE"
        $state.ValidationComplete = Invoke-ReleaseValidation
        Save-ReleaseState -State $state
        if (-not $state.ValidationComplete) { throw "Validation failed" }
    }
    
    # Step 3: Packaging
    if (-not $state.PackagingComplete) {
        Write-ReleaseLog "Step 3/5: Packaging..." "RELEASE"
        $state.PackagingComplete = Invoke-ReleasePackaging -Version $Version
        Save-ReleaseState -State $state
        if (-not $state.PackagingComplete) { throw "Packaging failed" }
    }
    
    # Step 4: Documentation
    if (-not $state.DocumentationComplete) {
        Write-ReleaseLog "Step 4/5: Documentation Finalization..." "RELEASE"
        $state.DocumentationComplete = Invoke-ReleaseDocumentation -Version $Version
        Save-ReleaseState -State $state
        if (-not $state.DocumentationComplete) { throw "Documentation failed" }
    }
    
    # Step 5: Execute Release
    Write-ReleaseLog "Step 5/5: Executing Release..." "RELEASE"
    
    # Create git tag
    $tagScript = "$PSScriptRoot\release_preparation.ps1"
    if (Test-Path $tagScript) {
        & $tagScript -Action Tag -Version $Version
    }
    
    # Record release
    $release = @{
        Version = $Version
        Date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Duration = ((Get-Date) - $startTime).TotalSeconds
        Success = $true
        Draft = $Draft
        Prerelease = $Prerelease
    }
    
    $state.Releases += $release
    $state.LastReleaseDate = $release.Date
    $state.CurrentVersion = $Version
    $state.Released = $true
    Save-ReleaseState -State $state
    
    Write-ReleaseLog "Release v$Version completed successfully!" "SUCCESS"
    Write-ReleaseLog "Duration: $([math]::Round($release.Duration, 2)) seconds" "INFO"
    
    return $release
}

function Publish-GitHubRelease {
    param(
        [string]$Version,
        [string]$Token
    )
    
    Write-ReleaseLog "Publishing GitHub release v$Version..." "RELEASE"
    
    if (-not $Token) {
        Write-ReleaseLog "GitHub token not provided" "WARN"
        return $false
    }
    
    # Read release notes
    $notesPath = Join-Path $ReleaseConfig.ArtifactsPath "RELEASE_NOTES_v$Version.md"
    $releaseNotes = if (Test-Path $notesPath) { 
        Get-Content $notesPath -Raw 
    } else { 
        "Release v$Version of $($ReleaseConfig.ProductName)" 
    }
    
    # Create release payload
    $releaseData = @{
        tag_name = "v$Version"
        target_commitish = $ReleaseConfig.DefaultBranch
        name = "v$Version"
        body = $releaseNotes
        draft = $Draft
        prerelease = $Prerelease
    } | ConvertTo-Json
    
    try {
        # Create release via GitHub API
        $headers = @{
            "Authorization" = "token $Token"
            "Content-Type" = "application/json"
        }
        
        $uri = "https://api.github.com/repos/$($ReleaseConfig.Repository)/releases"
        $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $releaseData
        
        Write-ReleaseLog "GitHub release created: $($response.html_url)" "SUCCESS"
        return $true
    }
    catch {
        Write-ReleaseLog "Failed to create GitHub release: $_" "ERROR"
        return $false
    }
}

function Verify-Release {
    param([string]$Version)
    
    Write-ReleaseLog "Verifying release v$Version..." "RELEASE"
    
    $checks = @{
        GitTag = $false
        PackageExists = $false
        DocumentationExists = $false
        AllPassed = $false
    }
    
    # Check git tag
    try {
        $tag = git tag -l "v$Version" 2>$null
        if ($tag) {
            $checks.GitTag = $true
            Write-ReleaseLog "Git tag verified: v$Version" "SUCCESS"
        }
        else {
            Write-ReleaseLog "Git tag not found: v$Version" "ERROR"
        }
    }
    catch {
        Write-ReleaseLog "Failed to verify git tag: $_" "ERROR"
    }
    
    # Check package exists
    $packagePath = Join-Path $ReleaseConfig.ArtifactsPath "$($ReleaseConfig.ProductName)-v$Version.zip"
    if (Test-Path $packagePath) {
        $checks.PackageExists = $true
        Write-ReleaseLog "Package verified: $packagePath" "SUCCESS"
    }
    else {
        Write-ReleaseLog "Package not found: $packagePath" "ERROR"
    }
    
    # Check documentation
    $docsPath = Join-Path $ReleaseConfig.ArtifactsPath "DOCUMENTATION_v$Version.md"
    if (Test-Path $docsPath) {
        $checks.DocumentationExists = $true
        Write-ReleaseLog "Documentation verified: $docsPath" "SUCCESS"
    }
    else {
        Write-ReleaseLog "Documentation not found: $docsPath" "WARN"
    }
    
    $checks.AllPassed = $checks.GitTag -and $checks.PackageExists
    
    return $checks
}

function Show-ReleaseStatus {
    $state = Get-ReleaseState
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║              RawrXD Release Status                              ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Current Version: $($state.CurrentVersion)" -ForegroundColor Cyan
    Write-Host "║ Last Release: $($state.LastReleaseDate)" -ForegroundColor Cyan
    Write-Host "║ Released: $($state.Released)" -ForegroundColor $(if($state.Released){"Green"}else{"Gray"})
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Release Steps:" -ForegroundColor Cyan
    Write-Host "║   [$(if($state.PreparationComplete){'x'}else{' '})] Preparation" -ForegroundColor $(if($state.PreparationComplete){"Green"}else{"Gray"})
    Write-Host "║   [$(if($state.ValidationComplete){'x'}else{' '})] Validation" -ForegroundColor $(if($state.ValidationComplete){"Green"}else{"Gray"})
    Write-Host "║   [$(if($state.PackagingComplete){'x'}else{' '})] Packaging" -ForegroundColor $(if($state.PackagingComplete){"Green"}else{"Gray"})
    Write-Host "║   [$(if($state.DocumentationComplete){'x'}else{' '})] Documentation" -ForegroundColor $(if($state.DocumentationComplete){"Green"}else{"Gray"})
    Write-Host "║   [$(if($state.Released){'x'}else{' '})] Released" -ForegroundColor $(if($state.Released){"Green"}else{"Gray"})
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    if ($state.Releases.Count -gt 0) {
        Write-Host "║ Release History:" -ForegroundColor Cyan
        foreach ($release in $state.Releases | Select-Object -Last 5) {
            $status = if ($release.Success) { "✓" } else { "✗" }
            $color = if ($release.Success) { "Green" } else { "Red" }
            Write-Host "║   $status v$($release.Version) - $($release.Date)" -ForegroundColor $color
        }
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
switch ($Action) {
    "Prepare" {
        if (-not $Version) {
            Write-ReleaseLog "Version parameter required" "ERROR"
            exit 1
        }
        $success = Invoke-ReleasePreparation -Version $Version
        exit ($success ? 0 : 1)
    }
    "Execute" {
        if (-not $Version) {
            Write-ReleaseLog "Version parameter required" "ERROR"
            exit 1
        }
        try {
            $result = Invoke-FullRelease -Version $Version
            $result | ConvertTo-Json -Depth 10
        }
        catch {
            Write-ReleaseLog "Release failed: $_" "ERROR"
            exit 1
        }
    }
    "Publish" {
        if (-not $Version) {
            Write-ReleaseLog "Version parameter required" "ERROR"
            exit 1
        }
        $success = Publish-GitHubRelease -Version $Version -Token $GitHubToken
        exit ($success ? 0 : 1)
    }
    "Verify" {
        if (-not $Version) {
            Write-ReleaseLog "Version parameter required" "ERROR"
            exit 1
        }
        $checks = Verify-Release -Version $Version
        $checks | ConvertTo-Json
        exit ($checks.AllPassed ? 0 : 1)
    }
    "ShowStatus" {
        Show-ReleaseStatus
    }
}
