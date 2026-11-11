# RawrXD Packaging
# Phase I Batch 3/5: Distribution Package Creation
# Creates distribution packages for release

param(
    [Parameter()]
    [ValidateSet("Create", "Validate", "Sign", "ShowStatus")]
    [string]$Action = "Create",
    
    [Parameter()]
    [string]$Version,
    
    [Parameter()]
    [string]$OutputPath = "$PSScriptRoot\artifacts\packages",
    
    [Parameter()]
    [string]$SourcePath = "$PSScriptRoot\..",
    
    [Parameter()]
    [ValidateSet("Zip", "NuGet", "MSI", "All")]
    [string]$PackageType = "All",
    
    [Parameter()]
    [string]$CertificateThumbprint,
    
    [Parameter()]
    [switch]$IncludeSource
)

# Package configuration
$PackageConfig = @{
    ProductName = "RawrXD"
    Description = "Sovereign AI Inference Runtime"
    Company = "RawrXD Project"
    Copyright = "Copyright (c) 2026 RawrXD Project"
    License = "MIT"
    MinPowerShellVersion = "7.0"
    
    IncludePaths = @(
        "governance",
        "analytics",
        "autonomous",
        "production",
        "release",
        "config",
        "docs",
        "README.md",
        "LICENSE"
    )
    
    ExcludePaths = @(
        "*.git*",
        "*.log",
        "*.tmp",
        "test-results",
        "node_modules",
        "bin",
        "obj",
        ".vs"
    )
}

# Ensure output directory exists
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

function Write-PackageLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    $logPath = "$PSScriptRoot\..\logs\packaging"
    if (-not (Test-Path $logPath)) {
        New-Item -ItemType Directory -Path $logPath -Force | Out-Null
    }
    $logFile = Join-Path $logPath "packaging_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "SUCCESS" { "Green" }
        "PACKAGE" { "Cyan" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function New-ZipPackage {
    param(
        [string]$Version,
        [string]$OutputDir
    )
    
    Write-PackageLog "Creating ZIP package for v$Version..." "PACKAGE"
    
    $packageName = "$($PackageConfig.ProductName)-v$Version.zip"
    $packagePath = Join-Path $OutputDir $packageName
    $tempDir = Join-Path $env:TEMP "rawrxd_package_$Version"
    
    # Clean up temp directory
    if (Test-Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    
    try {
        # Copy included paths
        foreach ($includePath in $PackageConfig.IncludePaths) {
            $source = Join-Path $SourcePath $includePath
            $dest = Join-Path $tempDir $includePath
            
            if (Test-Path $source) {
                if ((Get-Item $source).PSIsContainer) {
                    Copy-Item -Path $source -Destination $dest -Recurse -Force
                }
                else {
                    Copy-Item -Path $source -Destination $dest -Force
                }
                Write-PackageLog "Included: $includePath" "INFO"
            }
        }
        
        # Remove excluded paths
        foreach ($excludePattern in $PackageConfig.ExcludePaths) {
            Get-ChildItem -Path $tempDir -Recurse -Filter $excludePattern -ErrorAction SilentlyContinue | 
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        # Create version file
        $versionInfo = @{
            Version = $Version
            ProductName = $PackageConfig.ProductName
            Description = $PackageConfig.Description
            Company = $PackageConfig.Company
            Copyright = $PackageConfig.Copyright
            License = $PackageConfig.License
            MinPowerShellVersion = $PackageConfig.MinPowerShellVersion
            Packaged = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        $versionInfo | ConvertTo-Json | Out-File (Join-Path $tempDir "version.json") -Encoding UTF8
        
        # Create ZIP
        Compress-Archive -Path "$tempDir\*" -DestinationPath $packagePath -Force
        
        # Calculate hash
        $hash = Get-FileHash -Path $packagePath -Algorithm SHA256
        $hashPath = "$packagePath.sha256"
        $hash.Hash | Out-File $hashPath -Encoding UTF8
        
        Write-PackageLog "ZIP package created: $packagePath" "SUCCESS"
        
        # Cleanup
        Remove-Item -Path $tempDir -Recurse -Force
        
        return @{
            Type = "Zip"
            Path = $packagePath
            Hash = $hash.Hash
            HashPath = $hashPath
            Size = (Get-Item $packagePath).Length
        }
    }
    catch {
        Write-PackageLog "Failed to create ZIP package: $_" "ERROR"
        if (Test-Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        return $null
    }
}

function New-NuGetPackage {
    param(
        [string]$Version,
        [string]$OutputDir
    )
    
    Write-PackageLog "Creating NuGet package for v$Version..." "PACKAGE"
    
    $packageName = "$($PackageConfig.ProductName).$Version.nupkg"
    $packagePath = Join-Path $OutputDir $packageName
    $tempDir = Join-Path $env:TEMP "rawrxd_nuget_$Version"
    
    try {
        # Create NuGet structure
        New-Item -ItemType Directory -Path "$tempDir\tools" -Force | Out-Null
        New-Item -ItemType Directory -Path "$tempDir\content" -Force | Out-Null
        
        # Copy PowerShell modules
        foreach ($path in $PackageConfig.IncludePaths) {
            $source = Join-Path $SourcePath $path
            if (Test-Path $source) {
                Copy-Item -Path $source -Destination "$tempDir\content\$path" -Recurse -Force
            }
        }
        
        # Create nuspec
        $nuspec = @"<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
  <metadata>
    <id>$($PackageConfig.ProductName)</id>
    <version>$Version</version>
    <title>$($PackageConfig.ProductName)</title>
    <authors>$($PackageConfig.Company)</authors>
    <description>$($PackageConfig.Description)</description>
    <copyright>$($PackageConfig.Copyright)</copyright>
    <license type="expression">$($PackageConfig.License)</license>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
    <projectUrl>https://github.com/ItsMehRAWRXD/RawrXD</projectUrl>
    <tags>AI Inference Runtime Sovereign</tags>
  </metadata>
  <files>
    <file src="content\**\*.*" target="content\" />
    <file src="tools\**\*.*" target="tools\" />
  </files>
</package>
"@
        $nuspec | Out-File (Join-Path $tempDir "package.nuspec") -Encoding UTF8
        
        # Create package using nuget.exe if available
        $nugetExe = Get-Command nuget -ErrorAction SilentlyContinue
        if ($nugetExe) {
            & nuget pack (Join-Path $tempDir "package.nuspec") -OutputDirectory $OutputDir -Version $Version
            Write-PackageLog "NuGet package created: $packagePath" "SUCCESS"
        }
        else {
            Write-PackageLog "NuGet.exe not found, creating manual package" "WARN"
            # Create simple ZIP as fallback
            Compress-Archive -Path "$tempDir\*" -DestinationPath $packagePath -Force
        }
        
        # Cleanup
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        
        return @{
            Type = "NuGet"
            Path = $packagePath
            Size = if (Test-Path $packagePath) { (Get-Item $packagePath).Length } else { 0 }
        }
    }
    catch {
        Write-PackageLog "Failed to create NuGet package: $_" "ERROR"
        if (Test-Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        return $null
    }
}

function Invoke-PackageSigning {
    param([string]$PackagePath)
    
    if (-not $CertificateThumbprint) {
        Write-PackageLog "No certificate thumbprint provided, skipping signing" "WARN"
        return $false
    }
    
    Write-PackageLog "Signing package: $PackagePath" "PACKAGE"
    
    try {
        $cert = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $CertificateThumbprint }
        if ($null -eq $cert) {
            Write-PackageLog "Certificate not found: $CertificateThumbprint" "ERROR"
            return $false
        }
        
        # Sign the package
        Set-AuthenticodeSignature -FilePath $PackagePath -Certificate $cert -TimestampServer "http://timestamp.digicert.com"
        
        Write-PackageLog "Package signed successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-PackageLog "Failed to sign package: $_" "ERROR"
        return $false
    }
}

function Test-Package {
    param([hashtable]$Package)
    
    Write-PackageLog "Validating package: $($Package.Path)..." "PACKAGE"
    
    $results = @{
        Valid = $false
        Checks = @{}
    }
    
    # Check file exists
    $results.Checks.Exists = Test-Path $Package.Path
    
    # Check size
    if ($results.Checks.Exists) {
        $fileInfo = Get-Item $Package.Path
        $results.Checks.Size = $fileInfo.Length
        $results.Checks.SizeValid = $fileInfo.Length -gt 0
    }
    
    # Check hash if available
    if ($Package.HashPath -and (Test-Path $Package.HashPath)) {
        $expectedHash = Get-Content $Package.HashPath
        $actualHash = (Get-FileHash -Path $Package.Path -Algorithm SHA256).Hash
        $results.Checks.HashValid = $expectedHash -eq $actualHash
    }
    
    # Overall validation
    $results.Valid = $results.Checks.Exists -and $results.Checks.SizeValid
    
    if ($results.Valid) {
        Write-PackageLog "Package validation passed" "SUCCESS"
    }
    else {
        Write-PackageLog "Package validation failed" "ERROR"
    }
    
    return $results
}

function Show-PackageStatus {
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           RawrXD Packaging Status                               ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    if (Test-Path $OutputPath) {
        $packages = Get-ChildItem -Path $OutputPath -File
        Write-Host "║ Packages in $OutputPath`: $($packages.Count)" -ForegroundColor Cyan
        
        foreach ($package in $packages) {
            $size = if ($package.Length -gt 1MB) { 
                "$([math]::Round($package.Length / 1MB, 2)) MB" 
            } else { 
                "$([math]::Round($package.Length / 1KB, 2)) KB" 
            }
            Write-Host "║   $($package.Name) ($size)" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "║ No packages found" -ForegroundColor Yellow
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
switch ($Action) {
    "Create" {
        if (-not $Version) {
            Write-PackageLog "Version parameter required" "ERROR"
            exit 1
        }
        
        $packages = @()
        
        if ($PackageType -eq "All" -or $PackageType -eq "Zip") {
            $zipPackage = New-ZipPackage -Version $Version -OutputDir $OutputPath
            if ($zipPackage) {
                $packages += $zipPackage
            }
        }
        
        if ($PackageType -eq "All" -or $PackageType -eq "NuGet") {
            $nugetPackage = New-NuGetPackage -Version $Version -OutputDir $OutputPath
            if ($nugetPackage) {
                $packages += $nugetPackage
            }
        }
        
        # Output package info
        $packages | ConvertTo-Json -Depth 10
    }
    "Validate" {
        if (-not $Version) {
            Write-PackageLog "Version parameter required" "ERROR"
            exit 1
        }
        
        $zipPath = Join-Path $OutputPath "$($PackageConfig.ProductName)-v$Version.zip"
        if (Test-Path $zipPath) {
            $package = @{
                Path = $zipPath
                HashPath = "$zipPath.sha256"
            }
            $results = Test-Package -Package $package
            $results | ConvertTo-Json -Depth 10
        }
        else {
            Write-PackageLog "Package not found: $zipPath" "ERROR"
            exit 1
        }
    }
    "Sign" {
        if (-not $Version) {
            Write-PackageLog "Version parameter required" "ERROR"
            exit 1
        }
        
        $zipPath = Join-Path $OutputPath "$($PackageConfig.ProductName)-v$Version.zip"
        if (Test-Path $zipPath) {
            $success = Invoke-PackageSigning -PackagePath $zipPath
            exit ($success ? 0 : 1)
        }
        else {
            Write-PackageLog "Package not found: $zipPath" "ERROR"
            exit 1
        }
    }
    "ShowStatus" {
        Show-PackageStatus
    }
}
