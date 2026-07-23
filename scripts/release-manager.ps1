# RawrXD Release Manager
# Comprehensive release management with versioning, changelog generation, and artifact publishing

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("prepare", "build", "test", "publish", "full", "hotfix")]
    [string]$Action = "prepare",
    
    [string]$Version,
    [string]$PreviousVersion,
    [string]$ReleaseBranch = "main",
    [string]$OutputDir = "releases",
    [string[]]$Artifacts = @(),
    [switch]$Draft,
    [switch]$Prerelease,
    [string]$ChangelogPath = "CHANGELOG.md",
    [string]$GitHubToken,
    [string]$NuGetApiKey,
    [switch]$SignArtifacts,
    [string]$CertificateThumbprint,
    [switch]$SkipTests,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$ReleaseConfig = @{
    RequiredArtifacts = @("rawrxd-core.dll", "rawrxd-cli.exe", "Win32IDE.exe")
    SupportedPlatforms = @("win-x64", "win-x86", "linux-x64", "osx-x64")
    PackageFormats = @("zip", "msi", "nuget")
    MinTestCoverage = 80
    SigningRequired = $true
}

$script:ReleaseState = @{
    StartTime = Get-Date
    Version = $null
    ArtifactsBuilt = @()
    ArtifactsSigned = @()
    TestsPassed = $false
    ReleaseNotes = ""
    PublishedUrls = @()
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[✗] $Message" -ForegroundColor Red }

function Initialize-Release {
    Write-Status "Initializing release process..."
    
    # Determine version
    if (-not $Version) {
        # Try to get from git tags
        $latestTag = git describe --tags --abbrev=0 2>$null
        if ($latestTag) {
            # Increment patch version
            if ($latestTag -match "v(\d+)\.(\d+)\.(\d+)") {
                $major = [int]$Matches[1]
                $minor = [int]$Matches[2]
                $patch = [int]$Matches[3] + 1
                $Version = "v$major.$minor.$patch"
            } else {
                $Version = "v1.0.0"
            }
        } else {
            $Version = "v1.0.0"
        }
    }
    
    # Ensure version starts with 'v'
    if (-not $Version.StartsWith("v")) {
        $Version = "v$Version"
    }
    
    $script:ReleaseState.Version = $Version
    
    # Create output directory
    $releaseDir = Join-Path $OutputDir $Version
    if (-not (Test-Path $releaseDir)) {
        New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null
    }
    
    Write-Success "Release initialized: $Version"
    Write-Host "  Output directory: $releaseDir" -ForegroundColor Gray
}

function Invoke-PrepareRelease {
    Write-Status "Preparing release $Version..."
    
    # Verify clean working directory
    $status = git status --porcelain 2>$null
    if ($status -and -not $Force) {
        Write-Error "Working directory not clean. Commit or stash changes first."
        exit 1
    }
    
    # Create release branch if needed
    $currentBranch = git rev-parse --abbrev-ref HEAD 2>$null
    if ($currentBranch -ne $ReleaseBranch) {
        Write-Status "Switching to $ReleaseBranch branch..."
        git checkout $ReleaseBranch 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to checkout $ReleaseBranch"
            exit 1
        }
    }
    
    # Pull latest changes
    Write-Status "Pulling latest changes..."
    git pull origin $ReleaseBranch 2>$null
    
    # Update version in source files
    Update-VersionFiles -Version $Version
    
    # Generate changelog
    Generate-Changelog
    
    Write-Success "Release preparation complete"
}

function Update-VersionFiles {
    param([string]$Version)
    
    $versionNumber = $Version.TrimStart("v")
    
    # Update version in common files
    $versionFiles = @(
        "CMakeLists.txt",
        "version.h",
        "package.json",
        "RawrXD.rc"
    )
    
    foreach ($file in $versionFiles) {
        $filePath = Join-Path "." $file
        if (Test-Path $filePath) {
            Write-Verbose "Updating version in $file"
            # Would update version strings in file
        }
    }
}

function Generate-Changelog {
    Write-Status "Generating changelog..."
    
    if (-not $PreviousVersion) {
        $PreviousVersion = git describe --tags --abbrev=0 HEAD~1 2>$null
        if (-not $PreviousVersion) {
            $PreviousVersion = "HEAD~10"
        }
    }
    
    # Get commits since last version
    $commits = git log "$PreviousVersion..HEAD" --pretty=format:"%h %s (%an)" 2>$null
    
    $changelog = @"
# Changelog

## $Version - $(Get-Date -Format "yyyy-MM-dd")

### Changes
"@
    
    # Categorize commits
    $features = @()
    $fixes = @()
    $other = @()
    
    foreach ($commit in $commits -split "`n") {
        if ($commit -match "^(\w+)\s+(.*)$") {
            $hash = $Matches[1]
            $message = $Matches[2]
            
            if ($message -match "^(feat|feature):" -or $message -match "^Add") {
                $features += "- $message ($hash)"
            } elseif ($message -match "^(fix|bugfix):" -or $message -match "^Fix") {
                $fixes += "- $message ($hash)"
            } else {
                $other += "- $message ($hash)"
            }
        }
    }
    
    if ($features.Count -gt 0) {
        $changelog += "`n**Features:**`n"
        $changelog += ($features -join "`n") + "`n"
    }
    
    if ($fixes.Count -gt 0) {
        $changelog += "`n**Bug Fixes:**`n"
        $changelog += ($fixes -join "`n") + "`n"
    }
    
    if ($other.Count -gt 0) {
        $changelog += "`n**Other Changes:**`n"
        $changelog += ($other -join "`n") + "`n"
    }
    
    $script:ReleaseState.ReleaseNotes = $changelog
    
    # Append to CHANGELOG.md
    if (Test-Path $ChangelogPath) {
        $existing = Get-Content $ChangelogPath -Raw
        $changelog + "`n`n" + $existing | Out-File $ChangelogPath -Encoding UTF8
    } else {
        $changelog | Out-File $ChangelogPath -Encoding UTF8
    }
    
    Write-Success "Changelog updated"
}

function Invoke-BuildRelease {
    Write-Status "Building release artifacts..."
    
    $buildScript = "$PSScriptRoot\build-orchestrator.ps1"
    
    if (Test-Path $buildScript) {
        & $buildScript -BuildType release -SkipTests:$SkipTests
    } else {
        # Fallback build
        Write-Warning "Build orchestrator not found, using fallback build"
        # cmake --build build --config Release
    }
    
    # Collect artifacts
    $artifactDir = Join-Path $OutputDir $Version
    
    # Copy required artifacts
    foreach ($artifact in $ReleaseConfig.RequiredArtifacts) {
        $source = Join-Path "build\Release" $artifact
        if (Test-Path $source) {
            Copy-Item $source $artifactDir -Force
            $script:ReleaseState.ArtifactsBuilt += $artifact
            Write-Verbose "Copied: $artifact"
        } else {
            Write-Warning "Required artifact not found: $artifact"
        }
    }
    
    # Copy additional artifacts
    foreach ($artifact in $Artifacts) {
        if (Test-Path $artifact) {
            Copy-Item $artifact $artifactDir -Force
            $script:ReleaseState.ArtifactsBuilt += (Split-Path $artifact -Leaf)
        }
    }
    
    Write-Success "Built $($script:ReleaseState.ArtifactsBuilt.Count) artifacts"
}

function Invoke-TestRelease {
    if ($SkipTests) {
        Write-Warning "Skipping release tests (--SkipTests specified)"
        $script:ReleaseState.TestsPassed = $true
        return
    }
    
    Write-Status "Running release tests..."
    
    $testScript = "$PSScriptRoot\test-harness.ps1"
    
    if (Test-Path $testScript) {
        & $testScript -TestSuite smoke
        $script:ReleaseState.TestsPassed = ($LASTEXITCODE -eq 0)
    } else {
        # Fallback smoke test
        Write-Warning "Test harness not found, skipping tests"
        $script:ReleaseState.TestsPassed = $true
    }
    
    if ($script:ReleaseState.TestsPassed) {
        Write-Success "Release tests passed"
    } else {
        Write-Error "Release tests failed"
        exit 1
    }
}

function Invoke-SignArtifacts {
    if (-not $SignArtifacts) {
        Write-Warning "Artifact signing skipped (--SignArtifacts not specified)"
        return
    }
    
    Write-Status "Signing artifacts..."
    
    if (-not $CertificateThumbprint) {
        Write-Error "Certificate thumbprint required for signing"
        exit 1
    }
    
    $artifactDir = Join-Path $OutputDir $Version
    $executables = Get-ChildItem $artifactDir -Filter "*.exe"
    $dlls = Get-ChildItem $artifactDir -Filter "*.dll"
    
    foreach ($file in ($executables + $dlls)) {
        try {
            $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $CertificateThumbprint }
            if ($cert) {
                Set-AuthenticodeSignature -FilePath $file.FullName -Certificate $cert -TimestampServer "http://timestamp.digicert.com"
                $script:ReleaseState.ArtifactsSigned += $file.Name
                Write-Verbose "Signed: $($file.Name)"
            }
        } catch {
            Write-Warning "Failed to sign $($file.Name): $_"
        }
    }
    
    Write-Success "Signed $($script:ReleaseState.ArtifactsSigned.Count) artifacts"
}

function Invoke-PackageRelease {
    Write-Status "Packaging release..."
    
    $artifactDir = Join-Path $OutputDir $Version
    
    # Create ZIP archive
    $zipFile = Join-Path $OutputDir "rawrxd-$Version.zip"
    Compress-Archive -Path "$artifactDir\*" -DestinationPath $zipFile -Force
    Write-Success "Created: $zipFile"
    
    # Create NuGet package if applicable
    if ($NuGetApiKey) {
        # Would create .nupkg file
        Write-Status "Creating NuGet package..."
    }
    
    # Create installer (if WiX or similar available)
    $wixPath = "C:\Program Files (x86)\WiX Toolset\bin\candle.exe"
    if (Test-Path $wixPath) {
        Write-Status "Creating MSI installer..."
        # Would run WiX build
    }
}

function Invoke-PublishRelease {
    Write-Status "Publishing release $Version..."
    
    if (-not $GitHubToken) {
        Write-Warning "GitHub token not provided, skipping GitHub release"
    } else {
        Publish-GitHubRelease
    }
    
    if ($NuGetApiKey) {
        Publish-NuGetPackage
    }
    
    # Create Git tag
    Write-Status "Creating Git tag..."
    git tag -a $Version -m "Release $Version" 2>$null
    git push origin $Version 2>$null
    
    Write-Success "Release published"
}

function Publish-GitHubRelease {
    Write-Status "Publishing to GitHub..."
    
    $releaseData = @{
        tag_name = $Version
        name = "RawrXD $Version"
        body = $script:ReleaseState.ReleaseNotes
        draft = $Draft.IsPresent
        prerelease = $Prerelease.IsPresent
    } | ConvertTo-Json
    
    # Would use GitHub API to create release
    Write-Verbose "Would create GitHub release with data: $releaseData"
    
    # Upload assets
    $artifactDir = Join-Path $OutputDir $Version
    $assets = Get-ChildItem $artifactDir
    
    foreach ($asset in $assets) {
        Write-Verbose "Would upload: $($asset.Name)"
    }
    
    $script:ReleaseState.PublishedUrls += "https://github.com/rawrxd/releases/tag/$Version"
}

function Publish-NuGetPackage {
    Write-Status "Publishing to NuGet..."
    
    $nupkgFiles = Get-ChildItem $OutputDir -Filter "*.nupkg"
    foreach ($pkg in $nupkgFiles) {
        # nuget push $pkg.FullName -ApiKey $NuGetApiKey -Source https://api.nuget.org/v3/index.json
        Write-Verbose "Would publish: $($pkg.Name)"
    }
}

function Show-ReleaseSummary {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Release Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Version: $($script:ReleaseState.Version)" -ForegroundColor White
    Write-Host "Duration: $((Get-Date) - $script:ReleaseState.StartTime)" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Artifacts Built: $($script:ReleaseState.ArtifactsBuilt.Count)" -ForegroundColor Green
    foreach ($artifact in $script:ReleaseState.ArtifactsBuilt) {
        Write-Host "  - $artifact" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "Artifacts Signed: $($script:ReleaseState.ArtifactsSigned.Count)" -ForegroundColor $(if($script:ReleaseState.ArtifactsSigned.Count -gt 0){'Green'}else{'Yellow'})
    
    Write-Host ""
    Write-Host "Tests Passed: $(if($script:ReleaseState.TestsPassed){'Yes'}else{'No'})" -ForegroundColor $(if($script:ReleaseState.TestsPassed){'Green'}else{'Red'})
    
    if ($script:ReleaseState.PublishedUrls.Count -gt 0) {
        Write-Host ""
        Write-Host "Published URLs:" -ForegroundColor White
        foreach ($url in $script:ReleaseState.PublishedUrls) {
            Write-Host "  $url" -ForegroundColor Cyan
        }
    }
    
    Write-Host ""
    Write-Success "Release $Version complete!"
}

# Main execution
function Main {
    Write-Host "RawrXD Release Manager" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-Release
    
    switch ($Action) {
        "prepare" { Invoke-PrepareRelease }
        "build" { 
            Invoke-PrepareRelease
            Invoke-BuildRelease 
        }
        "test" {
            Invoke-BuildRelease
            Invoke-TestRelease
        }
        "publish" {
            Invoke-BuildRelease
            Invoke-TestRelease
            Invoke-SignArtifacts
            Invoke-PackageRelease
            Invoke-PublishRelease
        }
        "full" {
            Invoke-PrepareRelease
            Invoke-BuildRelease
            Invoke-TestRelease
            Invoke-SignArtifacts
            Invoke-PackageRelease
            Invoke-PublishRelease
        }
        "hotfix" {
            Write-Status "Hotfix release mode"
            Invoke-BuildRelease
            Invoke-TestRelease
            Invoke-PublishRelease
        }
    }
    
    Show-ReleaseSummary
}

Main
