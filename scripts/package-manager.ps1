# RawrXD Package Manager
# Manages packages, dependencies, and distribution

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Create", "Install", "Uninstall", "List", "Update", "Validate", "Publish")]
    [string]$Action = "List",
    
    [string]$PackageName = "",
    [string]$PackagePath = "",
    [string]$InstallPath = "packages",
    [string]$Repository = "https://packages.rawrxd.io",
    [string]$Version = "latest",
    [switch]$Force,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$script:PackageIndex = @{}
$script:InstalledPackages = @{}

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

function Initialize-PackageManager {
    Write-Status "Package Manager initialized"
    Write-Status "Action: $Action"
    Write-Status "Repository: $Repository"
    
    # Ensure install directory exists
    if (-not (Test-Path $InstallPath)) {
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    }
    
    # Load installed packages index
    $indexPath = "$InstallPath/.packages.json"
    if (Test-Path $indexPath) {
        $script:InstalledPackages = Get-Content $indexPath | ConvertFrom-Json
    }
}

function Get-PackageInfo {
    param([string]$Name)
    
    # Check local cache first
    $cachePath = "$InstallPath/$Name/package.json"
    if (Test-Path $cachePath) {
        return Get-Content $cachePath | ConvertFrom-Json
    }
    
    # Try to fetch from repository
    try {
        $url = "$Repository/packages/$Name.json"
        $response = Invoke-RestMethod -Uri $url -Method Get -ErrorAction SilentlyContinue
        return $response
    }
    catch {
        return $null
    }
}

function New-Package {
    if (-not $PackagePath) {
        $PackagePath = "."
    }
    
    if (-not $PackageName) {
        $PackageName = Split-Path $PackagePath -Leaf
    }
    
    Write-Status "Creating package: $PackageName"
    
    $packageJson = @{
        name = $PackageName
        version = if ($Version -ne "latest") { $Version } else { "1.0.0" }
        description = "RawrXD package"
        author = ""
        license = "MIT"
        dependencies = @{}
        files = @()
        entryPoint = ""
        rawrxdVersion = ">=3.0.0"
    }
    
    # Scan for files
    $files = Get-ChildItem -Path $PackagePath -File -Recurse |
        Where-Object { $_.Extension -in @(".gguf", ".json", ".yaml", ".txt", ".md") } |
        Select-Object -ExpandProperty FullName |
        ForEach-Object { $_.Substring($PackagePath.Length + 1) }
    
    $packageJson.files = $files
    
    # Save package.json
    $packageJson | ConvertTo-Json -Depth 5 | Out-File "$PackagePath/package.json"
    Write-Success "Package manifest created: $PackagePath/package.json"
    
    # Create package archive
    $archiveName = "$PackageName-$($packageJson.version).zip"
    $archivePath = "$PackagePath/$archiveName"
    
    if (-not $DryRun) {
        Compress-Archive -Path "$PackagePath/*" -DestinationPath $archivePath -Force
        Write-Success "Package archive created: $archivePath"
    }
}

function Install-Package {
    if (-not $PackageName) {
        Write-Error "PackageName required for Install action"
        return
    }
    
    Write-Status "Installing package: $PackageName"
    
    # Check if already installed
    if ($script:InstalledPackages.$PackageName -and -not $Force) {
        Write-Warning "Package '$PackageName' is already installed. Use -Force to reinstall."
        return
    }
    
    # Get package info
    $packageInfo = Get-PackageInfo -Name $PackageName
    if (-not $packageInfo) {
        Write-Error "Package '$PackageName' not found in repository"
        return
    }
    
    $versionToInstall = if ($Version -eq "latest") { $packageInfo.version } else { $Version }
    Write-Status "Version: $versionToInstall"
    
    if ($DryRun) {
        Write-Status "Would install: $PackageName@$versionToInstall"
        return
    }
    
    try {
        # Download package
        $downloadUrl = "$Repository/download/$PackageName/$versionToInstall.zip"
        $tempPath = "$env:TEMP/rawrxd-package-$PackageName-$(Get-Random).zip"
        
        Write-Status "Downloading from: $downloadUrl"
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempPath
        
        # Extract package
        $packageDir = "$InstallPath/$PackageName"
        if (Test-Path $packageDir) {
            Remove-Item -Path $packageDir -Recurse -Force
        }
        
        Expand-Archive -Path $tempPath -DestinationPath $packageDir -Force
        Remove-Item $tempPath
        
        # Update installed packages index
        $script:InstalledPackages[$PackageName] = @{
            version = $versionToInstall
            installed = Get-Date -Format "o"
            path = $packageDir
        }
        
        Save-PackageIndex
        
        Write-Success "Package '$PackageName' installed successfully"
        
        # Install dependencies
        if ($packageInfo.dependencies) {
            Write-Status "Installing dependencies..."
            foreach ($dep in $packageInfo.dependencies.PSObject.Properties) {
                Write-Status "Dependency: $($dep.Name) ($($dep.Value))"
                # Recursive install would go here
            }
        }
    }
    catch {
        Write-Error "Failed to install package: $_"
    }
}

function Uninstall-Package {
    if (-not $PackageName) {
        Write-Error "PackageName required for Uninstall action"
        return
    }
    
    Write-Status "Uninstalling package: $PackageName"
    
    if (-not $script:InstalledPackages.$PackageName) {
        Write-Error "Package '$PackageName' is not installed"
        return
    }
    
    $packageDir = "$InstallPath/$PackageName"
    
    if ($DryRun) {
        Write-Status "Would uninstall: $PackageName"
        return
    }
    
    try {
        if (Test-Path $packageDir) {
            Remove-Item -Path $packageDir -Recurse -Force
        }
        
        $script:InstalledPackages.Remove($PackageName)
        Save-PackageIndex
        
        Write-Success "Package '$PackageName' uninstalled successfully"
    }
    catch {
        Write-Error "Failed to uninstall package: $_"
    }
}

function Get-InstalledPackages {
    Write-Host ""
    Write-Host "Installed Packages" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    
    if ($script:InstalledPackages.Count -eq 0) {
        Write-Warning "No packages installed"
        return
    }
    
    foreach ($pkg in $script:InstalledPackages.GetEnumerator()) {
        Write-Host "  • $($pkg.Key)@$($pkg.Value.version)"
        Write-Host "    Path: $($pkg.Value.path)"
        Write-Host "    Installed: $($pkg.Value.installed)"
    }
    
    Write-Host ""
    Write-Host "Total: $($script:InstalledPackages.Count) packages"
}

function Update-Package {
    if (-not $PackageName) {
        Write-Error "PackageName required for Update action"
        return
    }
    
    Write-Status "Updating package: $PackageName"
    
    if (-not $script:InstalledPackages.$PackageName) {
        Write-Error "Package '$PackageName' is not installed"
        return
    }
    
    $currentVersion = $script:InstalledPackages.$PackageName.version
    $packageInfo = Get-PackageInfo -Name $PackageName
    
    if (-not $packageInfo) {
        Write-Error "Could not retrieve package information"
        return
    }
    
    if ($packageInfo.version -eq $currentVersion) {
        Write-Success "Package '$PackageName' is already up to date ($currentVersion)"
        return
    }
    
    Write-Status "Updating from $currentVersion to $($packageInfo.version)"
    
    # Uninstall old version
    Uninstall-Package
    
    # Install new version
    Install-Package
}

function Test-Package {
    if (-not $PackagePath) {
        $PackagePath = "."
    }
    
    Write-Status "Validating package at: $PackagePath"
    
    $manifestPath = "$PackagePath/package.json"
    if (-not (Test-Path $manifestPath)) {
        Write-Error "Package manifest not found: $manifestPath"
        return
    }
    
    try {
        $manifest = Get-Content $manifestPath | ConvertFrom-Json
        
        # Validate required fields
        $requiredFields = @("name", "version", "rawrxdVersion")
        foreach ($field in $requiredFields) {
            if (-not $manifest.$field) {
                Write-Error "Missing required field: $field"
                return
            }
        }
        
        # Validate files exist
        if ($manifest.files) {
            foreach ($file in $manifest.files) {
                $filePath = "$PackagePath/$file"
                if (-not (Test-Path $filePath)) {
                    Write-Error "Referenced file not found: $file"
                    return
                }
            }
        }
        
        Write-Success "Package validation passed"
    }
    catch {
        Write-Error "Package validation failed: $_"
    }
}

function Publish-Package {
    if (-not $PackagePath) {
        $PackagePath = "."
    }
    
    Write-Status "Publishing package from: $PackagePath"
    
    # Validate first
    Test-Package
    
    $manifestPath = "$PackagePath/package.json"
    $manifest = Get-Content $manifestPath | ConvertFrom-Json
    
    $archiveName = "$($manifest.name)-$($manifest.version).zip"
    $archivePath = "$PackagePath/$archiveName"
    
    if (-not (Test-Path $archivePath)) {
        Write-Error "Package archive not found. Run 'Create' action first."
        return
    }
    
    if ($DryRun) {
        Write-Status "Would publish: $archiveName to $Repository"
        return
    }
    
    Write-Status "Uploading to: $Repository"
    Write-Warning "Publishing to remote repositories requires authentication"
    Write-Status "Package ready for publishing: $archivePath"
}

function Save-PackageIndex {
    $indexPath = "$InstallPath/.packages.json"
    $script:InstalledPackages | ConvertTo-Json -Depth 3 | Out-File $indexPath
}

# Main execution
function Main {
    Write-Host "RawrXD Package Manager" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-PackageManager
    
    switch ($Action) {
        "Create" { New-Package }
        "Install" { Install-Package }
        "Uninstall" { Uninstall-Package }
        "List" { Get-InstalledPackages }
        "Update" { Update-Package }
        "Validate" { Test-Package }
        "Publish" { Publish-Package }
    }
    
    Write-Host ""
}

Main
